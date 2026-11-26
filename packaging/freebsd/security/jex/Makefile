PORTNAME=	jex
DISTVERSIONPREFIX=	v
DISTVERSION=	0.13.2
CATEGORIES=	security

MAINTAINER=	r.yerin@640kb.co.uk
COMMENT=	CryptoPro container reader and GOST CAdES/XAdES signing tool
WWW=		https://github.com/jex-crypto/jex

LICENSE=	AGPLv3+
LICENSE_FILE=	${WRKSRC}/LICENSE

LIB_DEPENDS=	libpcsclite.so:devel/pcsc-lite

USES=		cargo
USE_GITHUB=	yes
GH_ACCOUNT=	jex-crypto
GH_PROJECT=	jex

# One unit test requests a timestamp from a public TSA (no network in poudriere).
CARGO_TEST_ARGS=	-- --skip enveloped_xades_t_synthetic_with_cryptopro_tsa

PLIST_FILES=	bin/jex
PORTDOCS=	README.md

OPTIONS_DEFINE=		DOCS GUI
OPTIONS_DEFAULT=	GUI
GUI_DESC=		Graphical PIN dialog for the browser host (eframe)

# eframe/winit load X11, xkbcommon and OpenGL with dlopen(3) at run time.
GUI_USES=		gl xorg
GUI_USE=		GL=gl XORG=x11,xcursor,xi,xrandr
GUI_LIB_DEPENDS=	libxkbcommon.so:x11/libxkbcommon
GUI_VARS_OFF=		CARGO_FEATURES=--no-default-features

post-install:
	${STRIP_CMD} ${STAGEDIR}${PREFIX}/bin/jex

post-install-DOCS-on:
	@${MKDIR} ${STAGEDIR}${DOCSDIR}
	${INSTALL_DATA} ${WRKSRC}/README.md ${STAGEDIR}${DOCSDIR}

.include <bsd.port.mk>
