"""A Content-Security-Policy da aplicação, num lugar só.

Mora aqui, e não como texto solto dentro do `@after_request`, para que o teste
(`test_security_headers`) leia as diretivas sem importar a aplicação inteira.
O porquê de cada uma está em `BLUEPHISH_ARCHITECTURE.md` §4.5.
"""

# Nem `script-src` nem `style-src` têm 'unsafe-inline' (§7.4): nenhum onclick=, nenhum
# <script> embutido, nenhum style="" nem <style> no HTML. O layout pontual é uma
# classe u-* de bluephish.css; o JS aplica estilo pelo CSSOM (el(), node.style), que a
# CSP não governa. A única exceção é a tela de login com o reCAPTCHA ligado
# (captcha.login_csp), porque o script do Google injeta estilo inline.
# As quatro últimas diretivas não herdam `default-src`; sem elas a página poderia ser
# embutida em outro site, ganhar um <base href>, carregar plugin ou postar formulário
# para fora.
CONTENT_SECURITY_POLICY = (
	"default-src 'self'; img-src 'self' data:; "
	"style-src 'self' https://fonts.googleapis.com; "
	"font-src 'self' https://fonts.gstatic.com data:; "
	"script-src 'self' https://cdnjs.cloudflare.com; connect-src 'self'; "
	"frame-ancestors 'none'; base-uri 'self'; object-src 'none'; form-action 'self'"
)
