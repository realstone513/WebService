# Python Slim 이미지 사용
FROM python:3.11-slim

# 작업 디렉토리 설정
WORKDIR /app

# 의존성 파일 복사 및 설치
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

# Flask 애플리케이션 복사
COPY rearr.py .
COPY pj.env .

# Flask 실행
CMD ["python", "rearr.py"]