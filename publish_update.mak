
!INCLUDE $(NTMAKEENV)\makefile.plt

!if $(386)
_OUTCPU=i386
_OUTARC=x86
!elseif $(AMD64)
_OUTCPU=amd64
_OUTARC=x64
!else
!error unsupported.
!endif

!if $(FREEBUILD)
_OUTDIR=RelDir
_BUILDTYPE=fre
!else
_OUTDIR=DbgDir
_BUILDTYPE=chk
!endif

!if $(FREEBUILD)
!if $(386)
_BUILD_DIR  = .\objfre_win7_x86\i386
!elseif $(AMD64)
_BUILD_DIR  = .\objfre_win7_amd64\amd64
!else
!error unsupported.
!endif
!else
!if $(386)
_BUILD_DIR  = .\objchk_win7_x86\i386
!elseif $(AMD64)
_BUILD_DIR  = .\objchk_win7_amd64\amd64
!else
!error unsupported.
!endif
!endif

_PUBLISH_DIR = ..\..\FSWorkbench.Extensions\Runtime\$(_OUTCPU)\$(_OUTDIR)\ddk
_DEPLOY_DIR  = ..\..\FSWorkbench.Extensions\Runtime\svc\$(_OUTARC)\$(_BUILDTYPE)


######## Build Rule ########

all:
	copy $(_BUILD_DIR)\fsproxyopen.exe $(_PUBLISH_DIR)
	copy $(_BUILD_DIR)\fsproxyopen.pdb $(_PUBLISH_DIR)
	copy $(_BUILD_DIR)\fsproxyopen.exe $(_DEPLOY_DIR)
	copy $(_BUILD_DIR)\fsproxyopen.pdb $(_DEPLOY_DIR)

