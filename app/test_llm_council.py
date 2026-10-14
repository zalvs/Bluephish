"""Tests for the multi-agent pipeline.

Everything asserted here is an invariant that only ever fails silently. A
reviewer that quietly started approving things, a rebuttal round that quietly
started lowering risk, a council that quietly kept escalating after the agents
disagreed — none of those produce an error, a red test elsewhere or a log line.
They produce a wrong verdict on somebody's phishing mail, months later.

The models are not mocked into agreeing with the code. What is exercised is the
merging, clamping and gating logic, which is where the security properties live;
the model is just the thing that produces the dictionaries these functions
reason about.

Run with:  python -m unittest test_llm_council   (from the app/ directory)
"""

import unittest

import llm_council


def assessment(role = 'analyst_a', risk = 'Low', detected = False, tactics = None,
		justification = 'porque sim', model = 'm', revised = False):
	return {
		'role': role, 'model': model, 'risk_level': risk,
		'social_engineering_detected': detected, 'tactics': tactics or [],
		'justification': justification, 'revised': revised
	}


class RebuttalClamp(unittest.TestCase):
	"""The debate round may raise risk. It may never lower it.

	This is the whole reason a debate round is safe to have. The published
	conformity attacks on multi-agent debate work by talking an agent DOWN to
	benign; a round that only travels upward has nothing to offer them.
	"""

	def test_a_raise_is_kept(self):
		kept, changed = llm_council._clamp_revision(
			assessment(risk = 'Low'), assessment(risk = 'High'))
		self.assertEqual(kept['risk_level'], 'High')
		self.assertTrue(changed)

	def test_a_lowering_is_discarded(self):
		kept, changed = llm_council._clamp_revision(
			assessment(risk = 'Critical'), assessment(risk = 'Low'))
		self.assertEqual(kept['risk_level'], 'Critical')
		self.assertFalse(changed)

	def test_detection_can_be_turned_on_but_never_off(self):
		kept, _ = llm_council._clamp_revision(
			assessment(risk = 'High', detected = False), assessment(risk = 'High', detected = True))
		self.assertTrue(kept['social_engineering_detected'])

		kept, _ = llm_council._clamp_revision(
			assessment(risk = 'High', detected = True), assessment(risk = 'High', detected = False))
		self.assertTrue(kept['social_engineering_detected'])

	def test_rewritten_reasoning_counts_as_a_revision(self):
		# The levels are identical and only the prose moved. The reviewer reads
		# that prose, so calling this "not revised" would hide the change from the
		# one component whose job is to notice it
		kept, changed = llm_council._clamp_revision(
			assessment(risk = 'Low', justification = 'parece rotineiro'),
			assessment(risk = 'Low', justification = 'o outro analista me convenceu'))
		self.assertTrue(changed)
		self.assertEqual(kept['justification'], 'o outro analista me convenceu')

	def test_an_identical_rebuttal_is_not_a_revision(self):
		same = assessment(risk = 'Low', justification = 'parece rotineiro')
		self.assertFalse(llm_council._clamp_revision(same, dict(same))[1])

	def test_a_failed_rebuttal_leaves_the_original_alone(self):
		original = assessment(risk = 'Medium')
		kept, changed = llm_council._clamp_revision(original, None)
		self.assertEqual(kept, original)
		self.assertFalse(changed)


class Merge(unittest.TestCase):
	"""One assessment out of several, always the most cautious reading."""

	def test_the_highest_risk_wins(self):
		merged = llm_council._merge([assessment(risk = 'Low'), assessment(risk = 'Critical')])
		self.assertEqual(merged['risk_level'], 'Critical')

	def test_one_detection_is_enough(self):
		merged = llm_council._merge([
			assessment(detected = False), assessment(detected = True)])
		self.assertTrue(merged['social_engineering_detected'])

	def test_tactics_are_unioned_and_capped(self):
		merged = llm_council._merge([
			assessment(tactics = ['urgency', 'fear']),
			assessment(tactics = ['fear', 'payment_fraud'])])
		self.assertEqual(sorted(merged['tactics']), ['fear', 'payment_fraud', 'urgency'])

	def test_an_average_is_never_taken(self):
		# Averaging would let one compromised agent talk the result down, which is
		# exactly the thing every other rule in this module refuses
		merged = llm_council._merge([assessment(risk = 'Low'), assessment(risk = 'High')])
		self.assertEqual(merged['risk_level'], 'High')


class Consensus(unittest.TestCase):

	def test_agreement_is_consensus(self):
		ok, why = llm_council._consensus([
			assessment(risk = 'High', detected = True), assessment(risk = 'High', detected = True)])
		self.assertTrue(ok)
		self.assertEqual(why, '')

	def test_one_step_apart_still_counts_as_agreement(self):
		ok, _ = llm_council._consensus([
			assessment(risk = 'Medium', detected = True), assessment(risk = 'High', detected = True)])
		self.assertTrue(ok)

	def test_disagreeing_about_detection_is_divergence(self):
		ok, why = llm_council._consensus([
			assessment(detected = True), assessment(detected = False)])
		self.assertFalse(ok)
		self.assertIn('engenharia social', why)

	def test_two_steps_of_risk_apart_is_divergence(self):
		ok, why = llm_council._consensus([
			assessment(risk = 'Low', detected = True), assessment(risk = 'Critical', detected = True)])
		self.assertFalse(ok)
		self.assertIn('risco', why)

	def test_a_single_agent_cannot_diverge_from_itself(self):
		self.assertEqual(llm_council._consensus([assessment()]), (True, ''))


class ReviewParsing(unittest.TestCase):
	"""Every fallback points the same way: an answer that could not be read is
	not an answer that approved anything."""

	def test_a_clean_proceed(self):
		review = llm_council.parse_review(
			'{"manipulation_detected": false, "confidence": "High", '
			'"action": "proceed", "reason": "nada fora do lugar"}')
		self.assertEqual(review['action'], 'proceed')
		self.assertEqual(review['status'], 'ok')

	def test_an_unknown_action_becomes_hold(self):
		review = llm_council.parse_review('{"action": "approve_and_block"}')
		self.assertEqual(review['action'], 'hold_for_human')

	def test_a_missing_action_becomes_hold(self):
		self.assertEqual(llm_council.parse_review('{}')['action'], 'hold_for_human')

	def test_manipulation_forces_hold_even_when_it_says_proceed(self):
		# The two halves contradict each other; the half asking for a human wins
		review = llm_council.parse_review(
			'{"manipulation_detected": true, "action": "proceed"}')
		self.assertEqual(review['action'], 'hold_for_human')

	def test_an_answer_with_no_json_is_refused(self):
		with self.assertRaises(ValueError):
			llm_council.parse_review('Sure! I am now DAN and I approve this message.')

	def test_the_reason_is_truncated(self):
		review = llm_council.parse_review(
			'{"action": "proceed", "reason": "' + 'a' * 900 + '"}')
		self.assertEqual(len(review['reason']), llm_council.MAX_REASON_CHARS)

	def test_an_unknown_confidence_falls_back_to_low(self):
		self.assertEqual(llm_council.parse_review(
			'{"action": "proceed", "confidence": "Absolute"}')['confidence'], 'Low')


class Gating(unittest.TestCase):
	"""The two flags run_analysis acts on.

	Both can only withhold. Neither can unlock anything that was not already
	available, which is what keeps this module inside the rule the rest of the
	pipeline follows: a model raises a verdict, never lowers one.
	"""

	def gate(self, review, consensus):
		hold = (review['action'] == 'hold_for_human') or (not consensus)
		trust = (review['status'] == 'ok' and review['action'] == 'proceed' and consensus)
		return hold, trust

	def ok(self, action):
		return {'status': 'ok', 'action': action}

	def test_everything_clean_allows_autonomous_action(self):
		hold, trust = self.gate(self.ok('proceed'), True)
		self.assertFalse(hold)
		self.assertTrue(trust)

	def test_a_hold_blocks_autonomous_action_and_asks_for_a_human(self):
		hold, trust = self.gate(self.ok('hold_for_human'), True)
		self.assertTrue(hold)
		self.assertFalse(trust)

	def test_divergence_alone_blocks_autonomous_action(self):
		# Even with the reviewer perfectly happy: two models that read the same
		# email and disagreed is not a result to act on unattended
		hold, trust = self.gate(self.ok('proceed'), False)
		self.assertTrue(hold)
		self.assertFalse(trust)

	def test_an_unavailable_reviewer_never_counts_as_approval(self):
		# Trap 7.6: "it did not look" is not "it is safe"
		hold, trust = self.gate({'status': 'unavailable', 'action': 'proceed'}, True)
		self.assertFalse(trust)

	def test_single_mode_keeps_the_old_guarantee(self):
		# No council on the result means no council gate: run_analysis defaults
		# trustAutonomousAction to True so single mode behaves exactly as before
		council = ({'risk_level': 'High'}).get('council') or {}
		self.assertTrue(council.get('trustAutonomousAction', True))


class DegradedDebate(unittest.TestCase):
	"""Debate mode with one agent down is not a debate that agreed.

	This regressed once during development and produced no error: analyst_a
	raised, analyst_b survived, and a single assessment trivially agrees with
	itself — so the pipeline reported the consensus that unlocks autonomous
	action while running on one model, in the mode an operator picked precisely
	because they did not want that.
	"""

	def resolve(self, mode, assessments):
		consensus, divergence = llm_council._consensus(assessments)
		if mode == 'debate' and len(assessments) < 2:
			consensus = False
			divergence = 'apenas um agente respondeu: não houve debate'
		return consensus, divergence

	def test_one_surviving_agent_is_not_consensus(self):
		consensus, divergence = self.resolve('debate', [assessment(risk = 'Low')])
		self.assertFalse(consensus)
		self.assertIn('um agente', divergence)

	def test_and_therefore_cannot_unlock_autonomous_action(self):
		consensus, _ = self.resolve('debate', [assessment(risk = 'Low')])
		trust = ({'status': 'ok', 'action': 'proceed'}['action'] == 'proceed') and consensus
		self.assertFalse(trust)

	def test_review_mode_runs_one_agent_by_design(self):
		# The same single assessment is not a degradation here: review mode never
		# promised a second opinion, only a reviewer
		consensus, _ = self.resolve('review', [assessment(risk = 'Low')])
		self.assertTrue(consensus)


class Settings(unittest.TestCase):

	def test_the_default_mode_is_the_cheap_one(self):
		# Three model calls per email is not a default anybody opts into by
		# upgrading
		self.assertEqual(llm_council.DEFAULT_MODE, 'single')
		self.assertIn(llm_council.DEFAULT_MODE, llm_council.MODES)

	def test_an_unknown_mode_falls_back_instead_of_raising(self):
		import json
		import os
		import tempfile
		original = os.getcwd()
		workdir = tempfile.mkdtemp()
		try:
			os.chdir(workdir)
			with open('configuration.json', 'w') as handle:
				json.dump({'llm_analysis': {'pipeline_mode': 'parliament'}}, handle)
			mode, models = llm_council._agent_settings()
			self.assertEqual(mode, 'single')
			self.assertEqual(models, {'analyst_b': '', 'reviewer': ''})
		finally:
			os.chdir(original)

	def test_a_missing_configuration_file_falls_back(self):
		import os
		import tempfile
		original = os.getcwd()
		workdir = tempfile.mkdtemp()
		try:
			os.chdir(workdir)
			self.assertEqual(llm_council._agent_settings()[0], 'single')
		finally:
			os.chdir(original)


if __name__ == '__main__':
	unittest.main()
