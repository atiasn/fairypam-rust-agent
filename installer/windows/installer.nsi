Unicode true
ManifestDPIAware true
ManifestDPIAwareness PerMonitorV2
RequestExecutionLevel admin
SetCompressor /SOLID lzma

!include MUI2.nsh
!include LogicLib.nsh
!include x64.nsh
!include "installer-hooks.nsh"

!ifndef FAIRYPAM_PAYLOAD_ROOT
  !error "FAIRYPAM_PAYLOAD_ROOT is required"
!endif
!ifndef FAIRYPAM_OUTFILE
  !error "FAIRYPAM_OUTFILE is required"
!endif
!ifndef FAIRYPAM_VERSION
  !error "FAIRYPAM_VERSION is required"
!endif

!define PRODUCT_NAME "FairyPam"
!define UNINSTALL_KEY "Software\Microsoft\Windows\CurrentVersion\Uninstall\FairyPam"
!define FAIRYPAM_INSTALL_ROOT "$PROGRAMFILES64\${FAIRYPAM_INSTALL_DIRECTORY}"

Name "${PRODUCT_NAME}"
OutFile "${FAIRYPAM_OUTFILE}"
InstallDir "${FAIRYPAM_INSTALL_ROOT}"
VIProductVersion "${FAIRYPAM_VERSION}.0"
VIAddVersionKey "ProductName" "${PRODUCT_NAME}"
VIAddVersionKey "FileDescription" "FairyPam Windows Agent"
VIAddVersionKey "ProductVersion" "${FAIRYPAM_VERSION}"

!insertmacro MUI_PAGE_INSTFILES
!insertmacro MUI_UNPAGE_CONFIRM
!insertmacro MUI_UNPAGE_INSTFILES
!insertmacro MUI_LANGUAGE "SimpChinese"

!macro FP_DIR path
  !insertmacro FAIRYPAM_CREATE_OR_VERIFY_PROTECTED_DIRECTORY "${path}" fairypam_install_untrusted_security
!macroend

Function .onInit
  ${IfNot} ${RunningX64}
    Abort "FairyPam requires 64-bit Windows."
  ${EndIf}
  SetRegView 64
  SetShellVarContext all
FunctionEnd

Section "FairyPam" SEC_MAIN
  !insertmacro NSIS_HOOK_PREINSTALL

  !insertmacro FP_DIR "$INSTDIR\${FAIRYPAM_INSTALL_BOOTSTRAP_DIRECTORY}\payload\resources"
  !insertmacro FP_DIR "$INSTDIR\${FAIRYPAM_INSTALL_BOOTSTRAP_DIRECTORY}\payload\resources\runtime"
  !insertmacro FAIRYPAM_CREATE_OR_VERIFY_PROTECTED_FILE "$INSTDIR\${FAIRYPAM_INSTALL_BOOTSTRAP_DIRECTORY}\payload\resources\runtime\fairypam-agent-installer.exe" fairypam_install_untrusted_security
  SetOutPath "$INSTDIR\${FAIRYPAM_INSTALL_BOOTSTRAP_DIRECTORY}\payload\resources\runtime"
  File /oname=fairypam-agent-installer.exe "${FAIRYPAM_PAYLOAD_ROOT}\resources\runtime\fairypam-agent-installer.exe"
  ExecWait '"$INSTDIR\${FAIRYPAM_INSTALL_BOOTSTRAP_DIRECTORY}\payload\resources\runtime\fairypam-agent-installer.exe" --stop-shell "$INSTDIR"' $0
  ${If} $0 != 0
    StrCpy $R3 $0
    Goto fairypam_install_helper_failed
  ${EndIf}
  !insertmacro NSIS_HOOK_PREPAYLOAD

  !insertmacro FAIRYPAM_CREATE_OR_VERIFY_PROTECTED_FILE "$INSTDIR\fairypam-agent.exe" fairypam_install_untrusted_security
  SetOutPath "$INSTDIR"
  File "${FAIRYPAM_PAYLOAD_ROOT}\fairypam-agent.exe"
  !insertmacro FAIRYPAM_CREATE_OR_VERIFY_PROTECTED_FILE "$INSTDIR\fairypam-agent-guardian.exe" fairypam_install_untrusted_security
  File "${FAIRYPAM_PAYLOAD_ROOT}\fairypam-agent-guardian.exe"
  !insertmacro FAIRYPAM_CREATE_OR_VERIFY_PROTECTED_FILE "$INSTDIR\fairypam-agent-shell.exe" fairypam_install_untrusted_security
  File "${FAIRYPAM_PAYLOAD_ROOT}\fairypam-agent-shell.exe"
  !insertmacro FAIRYPAM_CREATE_OR_VERIFY_PROTECTED_FILE "$INSTDIR\fairypam-win32-worker.exe" fairypam_install_untrusted_security
  File "${FAIRYPAM_PAYLOAD_ROOT}\fairypam-win32-worker.exe"
  !insertmacro FAIRYPAM_CREATE_OR_VERIFY_PROTECTED_FILE "$INSTDIR\BUILD-MANIFEST.json" fairypam_install_untrusted_security
  File "${FAIRYPAM_PAYLOAD_ROOT}\BUILD-MANIFEST.json"

  !insertmacro FP_DIR "$INSTDIR\resources"
  !insertmacro FP_DIR "$INSTDIR\resources\runtime"
  !insertmacro FAIRYPAM_CREATE_OR_VERIFY_PROTECTED_FILE "$INSTDIR\resources\runtime\fairypam-agent-installer.exe" fairypam_install_untrusted_security
  SetOutPath "$INSTDIR\resources\runtime"
  File /oname=fairypam-agent-installer.exe "${FAIRYPAM_PAYLOAD_ROOT}\resources\runtime\fairypam-agent-installer.exe"

  !insertmacro FP_DIR "$INSTDIR\runtime"
  !insertmacro FP_DIR "$INSTDIR\runtime\maa"
  !insertmacro FP_DIR "$INSTDIR\runtime\maa\licenses"
  !insertmacro FP_DIR "$INSTDIR\runtime\maa\versions"
  !insertmacro FP_DIR "$INSTDIR\runtime\maa\versions\5.12.3"
  !insertmacro FP_DIR "$INSTDIR\runtime\maa\versions\5.12.3\bin"

  SetOutPath "$INSTDIR\runtime\maa"
  !insertmacro FAIRYPAM_CREATE_OR_VERIFY_PROTECTED_FILE "$INSTDIR\runtime\maa\THIRD-PARTY-NOTICES.md" fairypam_install_untrusted_security
  File "${FAIRYPAM_PAYLOAD_ROOT}\runtime\maa\THIRD-PARTY-NOTICES.md"
  !insertmacro FAIRYPAM_CREATE_OR_VERIFY_PROTECTED_FILE "$INSTDIR\runtime\maa\active.json" fairypam_install_untrusted_security
  File "${FAIRYPAM_PAYLOAD_ROOT}\runtime\maa\active.json"
  !insertmacro FAIRYPAM_CREATE_OR_VERIFY_PROTECTED_FILE "$INSTDIR\runtime\maa\maa-runtime.lock.json" fairypam_install_untrusted_security
  File "${FAIRYPAM_PAYLOAD_ROOT}\runtime\maa\maa-runtime.lock.json"
  !insertmacro FAIRYPAM_CREATE_OR_VERIFY_PROTECTED_FILE "$INSTDIR\runtime\maa\maa-runtime.manifest.json" fairypam_install_untrusted_security
  File "${FAIRYPAM_PAYLOAD_ROOT}\runtime\maa\maa-runtime.manifest.json"

  SetOutPath "$INSTDIR\runtime\maa\licenses"
  !insertmacro FAIRYPAM_CREATE_OR_VERIFY_PROTECTED_FILE "$INSTDIR\runtime\maa\licenses\MAA-LICENSE.md" fairypam_install_untrusted_security
  File "${FAIRYPAM_PAYLOAD_ROOT}\runtime\maa\licenses\MAA-LICENSE.md"

  SetOutPath "$INSTDIR\runtime\maa\versions\5.12.3"
  !insertmacro FAIRYPAM_CREATE_OR_VERIFY_PROTECTED_FILE "$INSTDIR\runtime\maa\versions\5.12.3\LICENSE.md" fairypam_install_untrusted_security
  File "${FAIRYPAM_PAYLOAD_ROOT}\runtime\maa\versions\5.12.3\LICENSE.md"

  SetOutPath "$INSTDIR\runtime\maa\versions\5.12.3\bin"
  !insertmacro FAIRYPAM_CREATE_OR_VERIFY_PROTECTED_FILE "$INSTDIR\runtime\maa\versions\5.12.3\bin\MaaFramework.dll" fairypam_install_untrusted_security
  File "${FAIRYPAM_PAYLOAD_ROOT}\runtime\maa\versions\5.12.3\bin\MaaFramework.dll"
  !insertmacro FAIRYPAM_CREATE_OR_VERIFY_PROTECTED_FILE "$INSTDIR\runtime\maa\versions\5.12.3\bin\MaaUtils.dll" fairypam_install_untrusted_security
  File "${FAIRYPAM_PAYLOAD_ROOT}\runtime\maa\versions\5.12.3\bin\MaaUtils.dll"
  !insertmacro FAIRYPAM_CREATE_OR_VERIFY_PROTECTED_FILE "$INSTDIR\runtime\maa\versions\5.12.3\bin\MaaWin32ControlUnit.dll" fairypam_install_untrusted_security
  File "${FAIRYPAM_PAYLOAD_ROOT}\runtime\maa\versions\5.12.3\bin\MaaWin32ControlUnit.dll"
  !insertmacro FAIRYPAM_CREATE_OR_VERIFY_PROTECTED_FILE "$INSTDIR\runtime\maa\versions\5.12.3\bin\fastdeploy_ppocr_maa.dll" fairypam_install_untrusted_security
  File "${FAIRYPAM_PAYLOAD_ROOT}\runtime\maa\versions\5.12.3\bin\fastdeploy_ppocr_maa.dll"
  !insertmacro FAIRYPAM_CREATE_OR_VERIFY_PROTECTED_FILE "$INSTDIR\runtime\maa\versions\5.12.3\bin\onnxruntime_maa.dll" fairypam_install_untrusted_security
  File "${FAIRYPAM_PAYLOAD_ROOT}\runtime\maa\versions\5.12.3\bin\onnxruntime_maa.dll"
  !insertmacro FAIRYPAM_CREATE_OR_VERIFY_PROTECTED_FILE "$INSTDIR\runtime\maa\versions\5.12.3\bin\opencv_world4_maa.dll" fairypam_install_untrusted_security
  File "${FAIRYPAM_PAYLOAD_ROOT}\runtime\maa\versions\5.12.3\bin\opencv_world4_maa.dll"

  SetOutPath "$INSTDIR"
  !insertmacro FAIRYPAM_CREATE_OR_VERIFY_PROTECTED_FILE "$INSTDIR\uninstall.exe" fairypam_install_untrusted_security
  WriteUninstaller "$INSTDIR\uninstall.exe"
  !insertmacro NSIS_HOOK_ACTIVATE

  WriteRegStr HKLM "${UNINSTALL_KEY}" "DisplayName" "${PRODUCT_NAME}"
  WriteRegStr HKLM "${UNINSTALL_KEY}" "DisplayVersion" "${FAIRYPAM_VERSION}"
  WriteRegStr HKLM "${UNINSTALL_KEY}" "Publisher" "FairyPam"
  WriteRegStr HKLM "${UNINSTALL_KEY}" "InstallLocation" "$INSTDIR"
  WriteRegStr HKLM "${UNINSTALL_KEY}" "DisplayIcon" "$INSTDIR\resources\runtime\fairypam-agent-installer.exe"
  WriteRegStr HKLM "${UNINSTALL_KEY}" "UninstallString" '$"$INSTDIR\uninstall.exe$"'
  WriteRegDWORD HKLM "${UNINSTALL_KEY}" "NoModify" 1
  WriteRegDWORD HKLM "${UNINSTALL_KEY}" "NoRepair" 1

  CreateDirectory "$SMPROGRAMS\FairyPam"
  CreateShortcut "$SMPROGRAMS\FairyPam\FairyPam.lnk" "$INSTDIR\resources\runtime\fairypam-agent-installer.exe" '--launch-shell "$INSTDIR"'
  CreateShortcut "$DESKTOP\FairyPam.lnk" "$INSTDIR\resources\runtime\fairypam-agent-installer.exe" '--launch-shell "$INSTDIR"'
SectionEnd

Function un.onInit
  SetRegView 64
  SetShellVarContext all
  StrCpy $INSTDIR "${FAIRYPAM_INSTALL_ROOT}"
  IfFileExists "$INSTDIR\resources\runtime\fairypam-agent-installer.exe" 0 un_invalid
  ExecWait '"$INSTDIR\resources\runtime\fairypam-agent-installer.exe" --stop-shell "$INSTDIR"' $0
  ${If} $0 != 0
    Goto un_invalid
  ${EndIf}
  ExecWait '"$INSTDIR\resources\runtime\fairypam-agent-installer.exe" --verify-uninstaller-copy "$INSTDIR" "$EXEPATH"' $0
  ${If} $0 != 0
    Goto un_invalid
  ${EndIf}
  Return
un_invalid:
  Abort "FairyPam could not safely stop or verify the installed Agent."
FunctionEnd

Section "Uninstall"
  ExecWait '"$INSTDIR\resources\runtime\fairypam-agent-installer.exe" --remove-runtime-state "$INSTDIR"' $0
  ${If} $0 != 0
    Abort "FairyPam could not safely remove its runtime state."
  ${EndIf}
  Delete "$DESKTOP\FairyPam.lnk"
  Delete "$SMPROGRAMS\FairyPam\FairyPam.lnk"
  RMDir "$SMPROGRAMS\FairyPam"
  DeleteRegKey HKLM "${UNINSTALL_KEY}"
  Delete "$INSTDIR\resources\runtime\fairypam-agent-installer.exe"
  Delete "$INSTDIR\uninstall.exe"
  Delete "$INSTDIR\current.json"
  RMDir /r "$INSTDIR\versions"
  RMDir /r "$INSTDIR\${FAIRYPAM_INSTALL_BOOTSTRAP_DIRECTORY}"
  RMDir "$INSTDIR\resources\runtime"
  RMDir "$INSTDIR\resources"
  RMDir "$INSTDIR"
SectionEnd
