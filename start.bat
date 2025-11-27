@echo OFF
echo Starting SmishingDetector...

REM Activate virtual environment
echo Activating virtual environment...
call venv\Scripts\activate

REM Start FastAPI server in the background
echo Starting FastAPI server in the background...
start "FastAPI Server" cmd /c "uvicorn api.main:app --host 0.0.0.0 --port 8000"

REM Wait a few seconds for the server to start
echo Waiting for API server to be ready...
timeout /t 5 /nobreak > NUL

REM Start Streamlit dashboard
echo Starting Streamlit dashboard...
streamlit run dashboard/app.py

echo.
echo SmishingDetector is running. The API is on port 8000 and the dashboard should open in your browser.
pause
