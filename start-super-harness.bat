@echo off
REM ============================================================================
REM  Deepseek super - start script (Windows)
REM
REM  First run: installs dependencies, builds any missing artifacts, creates
REM  the superagent profile inside .dsh, links the superagent plugin, and
REM  writes its config. Later runs skip straight to launch (.setup-done flag).
REM
REM  API key resolution (first hit wins):
REM    1. The harness credential store:  .dsh\.credentials.yaml
REM       (managed in the Web UI under Models; seated by Cho-zen1 - the
REM        package intentionally ships without it)
REM    2. DEEPSEEK_API_KEY from the environment (the Windows User environment
REM       variable is inherited by this window automatically)
REM    3. DEEPSEEK_API_KEY from a .env file in this folder
REM ============================================================================
setlocal
cd /d "%~dp0"
set "ROOT=%~dp0"
set "DSH_HOME=%ROOT%.dsh"
if not exist "%DSH_HOME%" mkdir "%DSH_HOME%"
if not exist "%ROOT%state\superagent" mkdir "%ROOT%state\superagent"

REM --- key route 3: .env in this folder (route 2 is the inherited env) -------
if not defined DEEPSEEK_API_KEY (
  if exist "%ROOT%.env" (
    for /f "usebackq tokens=1,* delims==" %%A in ("%ROOT%.env") do (
      if /i "%%A"=="DEEPSEEK_API_KEY" set "DEEPSEEK_API_KEY=%%B"
    )
  )
)

REM --- first-run setup --------------------------------------------------------
if not exist "%ROOT%.setup-done" (
  echo [setup] First run: installing the harness dependencies - needs internet, takes a few minutes...
  pushd "%ROOT%src\deepseek-harness"
  call pnpm install
  if errorlevel 1 goto :setupfail
  if not exist "apps\web\dist" (
    echo [setup] Building harness artifacts...
    call pnpm run build:artifacts
    if errorlevel 1 goto :setupfail
  )
  popd

  echo [setup] Installing and building the superagent prototype...
  pushd "%ROOT%src\dsh-superagent-prototype"
  call pnpm install
  if errorlevel 1 goto :setupfail
  call pnpm run build
  if errorlevel 1 goto :setupfail
  popd

  echo [setup] Creating the superagent profile and linking the plugin...
  pushd "%ROOT%src\deepseek-harness"
  call pnpm dsh superagent --from-default-profile web --dump-config > nul
  call pnpm dsh plugin --profile superagent add "link:%ROOT%src\dsh-superagent-prototype"
  if errorlevel 1 goto :setupfail
  popd

  echo [setup] Writing the superagent profile config...
  > "%DSH_HOME%\profiles\superagent\cordis.patch.yml" echo # Superagent profile config for this package (written by start-super-harness.bat).
  >>"%DSH_HOME%\profiles\superagent\cordis.patch.yml" echo - id: webserver
  >>"%DSH_HOME%\profiles\superagent\cordis.patch.yml" echo   config:
  >>"%DSH_HOME%\profiles\superagent\cordis.patch.yml" echo     host: 127.0.0.1
  >>"%DSH_HOME%\profiles\superagent\cordis.patch.yml" echo     port: 3082
  >>"%DSH_HOME%\profiles\superagent\cordis.patch.yml" echo - id: dsh-superagent
  >>"%DSH_HOME%\profiles\superagent\cordis.patch.yml" echo   config:
  >>"%DSH_HOME%\profiles\superagent\cordis.patch.yml" echo     stateDir: %ROOT%state\superagent

  echo done> "%ROOT%.setup-done"
  echo [setup] Setup complete.
)

REM --- launch ------------------------------------------------------------------
echo Starting the DeepSeek Harness Web UI  - http://127.0.0.1:3080
echo Starting the Superagent profile       - http://127.0.0.1:3082
echo Each server window prints a tokenized URL - open THAT url in the browser.
echo Keep both server windows open while testing. Close them to stop.
start "DSH Web UI - 3080" cmd /k "cd /d %ROOT%src\deepseek-harness && pnpm dsh web --no-open"
start "DSH Superagent - 3082" cmd /k "cd /d %ROOT%src\deepseek-harness && pnpm dsh --profile superagent --no-open"
endlocal
exit /b 0

:setupfail
echo [setup] FAILED - see the error above. Fix it (usually: pnpm missing or no internet) and run this script again.
popd
pause
endlocal
exit /b 1
