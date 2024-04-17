import asyncio
import time
from jose import JWTError, jwt
from unidecode import unidecode
from config.config import SECRET_KEY, ALGORITHM
from fastapi.security import OAuth2PasswordBearer
from fastapi import HTTPException, Depends, status
from base.class_base import Admin, OTP, Service, ServiceDuration, Users, Location, Promotion, Slides, Blog, Partner, \
    AcceptJob
from jose import JWTError, jwt
import random
from sqlalchemy.orm import Session
from sqlalchemy import desc
from datetime import datetime, timedelta
import secrets
import string

# Thêm danh sách đen cho token
token_blacklist: set = set()

# OAuth2PasswordBearer cho việc xác thực token
oauth2_scheme = OAuth2PasswordBearer(tokenUrl="token")


def random_id(K: int = 5):
    randoms = ''.join(random.choices('0123456789', k=K))
    return randoms

def convert_string(input_string):
    processed_string = unidecode(input_string).replace(" ", "").lower()
    return processed_string

def convert_date(input_date):
    processed_date = input_date.replace("/", "")
    return processed_date

current_date = datetime.now().strftime("%d/%m/%Y")


# Hàm tạo JWT token
def create_jwt_token(data: dict):
    data["iat"] = time.time()
    return jwt.encode(data, SECRET_KEY, algorithm=ALGORITHM)

def generate_referral_code(length=6):
    alphabet = string.ascii_letters + string.digits
    code = ''.join(secrets.choice(alphabet) for _ in range(length))
    return code


def get_weekday_string(working_day):

    today = datetime.now().date()
    print(working_day)
    print(today)
    if working_day.weekday() == 0:
        return "Thứ 2"
    elif working_day.weekday() == 1:
        return "Thứ 3"
    elif working_day.weekday() == 2:
        return "Thứ 4"
    elif working_day.weekday() == 3:
        return "Thứ 5"
    elif working_day.weekday() == 4:
        return "Thứ 6"
    elif working_day.weekday() == 5:
        return "Thứ 7"
    elif working_day.weekday() == 6:
        return "Chủ Nhật"
    else:
        return "Không xác định"


def get_date_range(start_date_str, end_date_str):
    # Chuyển đổi chuỗi ngày tháng thành đối tượng datetime
    start_date = datetime.strptime(start_date_str, "%Y-%m-%d")
    end_date = datetime.strptime(end_date_str, "%Y-%m-%d")

    # Khởi tạo danh sách chứa các ngày trong khoảng thời gian
    date_range = []
    current_date = start_date

    # Duyệt qua từng ngày trong khoảng thời gian và thêm vào danh sách
    while current_date <= end_date:
        # Lấy thứ của ngày hiện tại
        weekday = get_weekday_string(current_date.strftime("%Y-%m-%d"))
        # Thêm ngày và thứ vào danh sách
        date_range.append((current_date.strftime("%d/%m/%Y"), weekday))
        # Tăng giá trị ngày lên 1
        current_date += timedelta(days=1)

    return date_range
def extract_indexes(input_string):
    # Tạo một danh sách để lưu trữ các chỉ số của các số 1
    indexes = []

    # Chuyển đổi chuỗi thành danh sách các số
    numbers = [int(x) for x in input_string.split(",")]

    # Lặp qua từng số trong danh sách
    for i, num in enumerate(numbers, start=1):
        # Nếu số là 1, thêm chỉ số vào danh sách
        if num == 1:
            indexes.append(i)

    # Trả về danh sách các chỉ số có giá trị là 1
    return indexes

# Hàm xác minh JWT token
def verify_jwt_token(token: str = Depends(oauth2_scheme)):
    if token in token_blacklist:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Token has been invalidated",
            headers={"WWW-Authenticate": "Bearer"},
        )
    try:
        payload = jwt.decode(token, SECRET_KEY, algorithms=[ALGORITHM])
        return payload
    except JWTError:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Invalid credentials",
            headers={"WWW-Authenticate": "Bearer"},
        )

# Hàm lấy thông tin người dùng từ cơ sở dữ liệu
async def get_admin(db, username: str):
    query = Admin.__table__.select().where(Admin.username == username)
    user = await db.fetch_one(query)
    return user

async def get_users(db, email: str):
    query = Users.__table__.select().where(Users.email == email)
    user = await db.fetch_one(query)
    return user

async def get_partner(db, email: str):
    query = Partner.__table__.select().where(Partner.email == email)
    user = await db.fetch_one(query)
    return user

async def get_partner_id(db, id: str):
    query = Partner.__table__.select().where(Partner.id == id)
    user = await db.fetch_one(query)
    return user

async def delete_otp_after_delay(email: str, db: Session):
    await asyncio.sleep(60)
    delete_query = OTP.__table__.delete().where(OTP.email == email)
    await db.execute(delete_query)

async def get_select_service_duration(db):
    query = ServiceDuration.__table__.select()
    service_duration = await db.fetch_all(query)
    return service_duration

async def get_select_service(db):
    query = Service.__table__.select()
    service = await db.fetch_all(query)
    return service

async def get_select_promotion(db):
    query = Promotion.__table__.select()
    promotion = await db.fetch_all(query)
    return promotion

async def get_select_promotion_id(db, id:str):
    query = Promotion.__table__.select().where(Promotion.id == id)
    promotion = await db.fetch_all(query)
    return promotion

async def get_select_slides(db):
    query = Slides.__table__.select()
    slides = await db.fetch_all(query)
    return slides

async def get_select_blog(db):
    query = Blog.__table__.select()
    blog = await db.fetch_all(query)
    return blog


async def get_db_location_defaultt(db,id:str):
    query = Location.__table__.select().order_by(desc(Location.defaultt)).where((Location.id_users == id) & (Location.defaultt == 1))
    service = await db.fetch_all(query)
    return service

async def get_db_location(db,id:str):
    query = Location.__table__.select().order_by(desc(Location.defaultt)).where(Location.id_users == id)
    service = await db.fetch_all(query)
    return service

async def get_db_user(db,id:str):
    query = (Users.__table__.select().where(Users.id == id))
    service = await db.fetch_all(query)
    return service

async  def get_delete_location(db, id:str):
    query = Location.__table__.delete().where(Location.id == id)
    await db.execute(query)

async def get_delete_slide(db, id: str):
    query = Slides.__table__.delete().where(Slides.id == id)
    await db.execute(query)




