from sqlalchemy import Column, Integer, String, ForeignKey
from sqlalchemy.orm import relationship
from sqlalchemy.ext.declarative import declarative_base

Base = declarative_base()

class Admin(Base):
    __tablename__ = "admin"

    id = Column(String, primary_key=True)
    id_admin = Column(String, nullable=False)
    username = Column(String, nullable=False)
    password = Column(String, nullable=False)
    email = Column(String)
    phonenumber = Column(String, nullable=False)
    name = Column(String, nullable=False)
    sex = Column(Integer, nullable=False)
    datebirth = Column(String, nullable=False)
    image = Column(String)
    permanent_address = Column(String, nullable=False)
    temporary_residence_address = Column(String, nullable=False)
    position = Column(String)
    joiningdate = Column(String, nullable=False)
    role = Column(Integer, nullable=False)
    status = Column(Integer, nullable=False)

class OTP(Base):
    __tablename__ = "otp"

    id = Column(String, primary_key=True, index=True)
    email = Column(String, index=True)
    code = Column(String)
    name = Column(String)

class ResetPasswords(Base):
    __tablename__ = "reset_password"

    id = Column(String, primary_key=True, index=True)
    id_user = Column(String)
    token = Column(String)

class Promotion(Base):
    __tablename__ = "promotion"

    id = Column(String, primary_key=True)
    name = Column(String, nullable=False)
    code = Column(String)
    start_day = Column(String, nullable=False)
    end_day = Column(String, nullable=False)
    content = Column(String, nullable=False)
    label = Column(Integer, nullable=False)
    discount = Column(Integer, nullable=False)
    point = Column(Integer, nullable=False)
    id_admin = Column(String, nullable=False)

class Slides(Base):
    __tablename__ = "slides"

    id = Column(String, primary_key=True)
    imageUrl = Column(String, nullable=False)
    newsUrl = Column(String)
    date = Column(String, nullable=False)
    id_admin = Column(String, nullable=False)

class Blog(Base):
    __tablename__ = "blog"

    id = Column(String, primary_key=True)
    imageUrl = Column(String, nullable=False)
    newsUrl = Column(String)
    title = Column(String)
    content = Column(String)
    date = Column(String)
    status = Column(Integer)
    id_admin = Column(String, nullable=False)

class Users(Base):
    __tablename__ = "users"

    id = Column(String, primary_key=True)
    password = Column(String, nullable=False)
    phoneNumber = Column(String, nullable=False)
    email = Column(String)
    name = Column(String, nullable=False)
    image = Column(String, nullable=False)
    money = Column(Integer, nullable=False)
    g_points = Column(Integer, nullable=False)
    sex = Column(Integer, nullable=False)
    datebirth = Column(String, nullable=False)
    ban = Column(Integer, nullable=False)
    yourReferralCode = Column(String)
    referralCode = Column(String)


class CustomerPromotions(Base):
    __tablename__ = "customer_promotions"

    id = Column(String, primary_key=True)
    id_users = Column(String, ForeignKey('users.id'), nullable=False)
    id_promotion = Column(String, ForeignKey('promotion.id'), nullable=False)
    status = Column(Integer, nullable=False)

class Notification(Base):
    __tablename__ = "notification"
    id = Column(String, primary_key=True)
    id_invoice_details = Column(String, nullable=False)
    id_users = Column(String, nullable=False)
    title = Column(String, ForeignKey('promotion.id'), nullable=False)
    content = Column(String, nullable=False)
    posting_time = Column(String, nullable=False)
    status_notification = Column(Integer, nullable=False)

class Partner(Base):
    __tablename__ = "partner"

    id = Column(String, primary_key=True)
    id_admin = Column(String, ForeignKey('admin.id'), nullable=False)
    email = Column(String)
    phonenumber = Column(String, nullable=False)
    password = Column(String)
    name = Column(String, nullable=False)
    one_star = Column(Integer, nullable=False)
    two_star = Column(Integer, nullable=False)
    three_star = Column(Integer, nullable=False)
    four_star = Column(Integer, nullable=False)
    five_star = Column(Integer, nullable=False)
    service = Column(String, nullable=False)
    image = Column(String)
    datebirth = Column(String, nullable=False)
    cccd = Column(String, nullable=False)
    date_cccd = Column(String, nullable=False)
    address = Column(String, nullable=False)
    sex = Column(Integer, nullable=False)
    date = Column(String, nullable=False)
    money = Column(Integer, nullable=False)
    ban = Column(Integer, nullable=False)
    censorship = Column(Integer, nullable=False)

class BalanceFluctuations(Base):
    __tablename__ = "balance_fluctuations"

    id = Column(String, primary_key=True)
    id_customer = Column(String, nullable=False)
    money = Column(Integer, nullable=False)
    note = Column(String, nullable=False)
    date = Column(String, nullable=False)
    status = Column(String, nullable=False)
    wallet =Column(String, nullable=False)
class Invoice(Base):
    __tablename__ = "invoice"

    id = Column(String(), primary_key=True)
    label = Column(Integer, nullable=False)
    id_users = Column(String(), ForeignKey('users.id'), nullable=False)
    repeat = Column(String())
    duration = Column(String())
    repeat_state = Column(Integer, nullable=False)
    cancel_repeat = Column(Integer, nullable=False)
    removal_date = Column(String, nullable=False)

class InvoiceDetails(Base):
    __tablename__ = "invoice_details"

    id = Column(String(), primary_key=True)
    id_invoice = Column(String(), ForeignKey('invoice.id'), nullable=False)
    id_partner = Column(String())
    name_user = Column(String(), nullable=False)
    phone_number = Column(String(), nullable=False)
    location = Column(String(), nullable=False)
    location2 = Column(String(), nullable=False)
    lat = Column(String(), nullable=False)
    lng = Column(String(), nullable=False)
    pet_note = Column(String())
    employee_note = Column(String())
    posting_time = Column(String(), nullable=False)
    working_day = Column(String(), nullable=False)
    work_time = Column(String(), nullable=False)
    room_area = Column(String(), nullable=False)
    price = Column(Integer, nullable=False)
    payment_methods = Column(Integer, nullable=False)
    order_status = Column(Integer, nullable=False)
    premium_service = Column(Integer)
    number_sessions = Column(String)
    reason_cancellation = Column(String)
    cancellation_time_completed = Column(String)
    cancel_job = Column(String)
    cancellation_fee = Column(Integer)

class LoaiBoCV(Base):
    __tablename__ = "loai_bo_cv"

    id = Column(String, primary_key=True)
    id_invoice_details = Column(String, nullable=False)
    id_partner = Column(String, nullable=False)

class AcceptJob(Base):
    __tablename__ = "accept_job"

    id = Column(String(), primary_key=True)
    id_invoice_details = Column(String(), ForeignKey('invoice_details.id'), nullable=False)
    id_partner = Column(String())
    status = Column(Integer)
class Service(Base):
    __tablename__ = "service"

    id = Column(String, primary_key=True)
    id_admin = Column(String, nullable=False)
    name = Column(String, nullable=False)
    icon = Column(String, nullable=False)
    label = Column(Integer)
    status = Column(Integer)

class ServiceDuration(Base):
    __tablename__ = "service_duration"

    id = Column(String, primary_key=True)
    id_admin=Column(String)
    time = Column(Integer)
    acreage = Column(String)
    room = Column(String, nullable=False)
    money = Column(Integer, nullable=False)
    status = Column(Integer)

class OrderDetails(Base):
    __tablename__ = "order_details"

    id = Column(String, primary_key=True)
    invoice_id = Column(String, ForeignKey('invoice.id'), nullable=False)
    id_service_duration = Column(String, ForeignKey('service_duration.id'))
    repeat = Column(String)
    working_day = Column(String)
    end_date = Column(String)
    work_time = Column(String)
    now_start_working = Column(String)
    option = Column(String)
    extra_service = Column(String)
    note = Column(String)

class TotalSanitation(Base):
    __tablename__ = "total_sanitation"

    id = Column(String, primary_key=True)
    id_users = Column(String, ForeignKey('users.id'), nullable=False)
    note = Column(String, nullable=False)
    address = Column(String, nullable=False)

class AddServices(Base):
    __tablename__ = "add_services"

    id = Column(String, primary_key=True)
    icon = Column(String, nullable=False)
    name = Column(String, nullable=False)
    note = Column(String, nullable=False)
    money = Column(Integer, nullable=False)



class Evaluate(Base):
    __tablename__ = "evaluate"

    id = Column(String, primary_key=True)
    id_partner = Column(String, nullable=False)
    id_user = Column(String,  nullable=False)
    star = Column(Integer, nullable=False)
    date = Column(String, nullable=False)
    content = Column(String, nullable=False)
    image = Column(String)

class Location(Base):
    __tablename__ = "location"

    id = Column(String, primary_key=True)
    id_users = Column(String, ForeignKey('users.id'), nullable=False)
    location = Column(String, nullable=False)
    location2 = Column(String, nullable=False)
    lat = Column(String, nullable=False)
    lng = Column(String, nullable=False)
    defaultt = Column(Integer, nullable=False)

class TinNhan(Base):
    __tablename__ = "tin_nhan"

    id = Column(String, primary_key=True)
    id_nguoi_gui = Column(String, nullable=False)
    id_phong_chat = Column(String, nullable=False)
    noi_dung = Column(String, nullable=False)
    thoi_gian = Column(String, nullable=False)

class PhongChat(Base):
    __tablename__ = "phong_chat"

    id = Column(String, primary_key=True)
    tin_nhan_cuoi_cung = Column(String, nullable=False)
    thoi_gian = Column(String, nullable=False)
    thoi_gian_tao_phong = Column(String, nullable=False)

class ThanhVienChat(Base):
    __tablename__ = "thanh_vien_chat"

    id = Column(String, primary_key=True)
    id_user = Column(String, nullable=False)
    id_phong_chat = Column(String, nullable=False)
    da_doc = Column(Integer, nullable=False)

