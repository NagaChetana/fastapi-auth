FASTAPI SETUP & RUN GUIDE

Install required packages:
pip install fastapi uvicorn sqlalchemy passlib[bcrypt] pydantic

Run the FastAPI server (inside folder where main.py exists):
python -m uvicorn main:app --reload

Server runs on PORT: 8000

Home Route (API check):
http://127.0.0.1:8000/ → FastAPI running message

FastAPI Swagger UI:
http://127.0.0.1:8000/docs → Test Register & Login APIs here
