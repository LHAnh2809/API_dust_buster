
import os
from uuid import uuid4
from fastapi.responses import FileResponse
from starlette.middleware.cors import CORSMiddleware
from starlette.websockets import WebSocketState

from config.config import DATABASE_URL
from fastapi import FastAPI, File, HTTPException, Depends, BackgroundTasks, UploadFile, status
from sqlalchemy import create_engine, select, update, desc, text
from sqlalchemy.orm import sessionmaker, Session
from databases import Database
from base.class_base import OTP, Base, Admin, Service, ServiceDuration, Users, Location, Promotion, Slides, Blog, \
    CustomerPromotions, Invoice, InvoiceDetails, AcceptJob, Notification, Partner, BalanceFluctuations, Evaluate, \
    LoaiBoCV, TinNhan, PhongChat, ThanhVienChat
from base.base_model import CreateAdmin, CreateLocation, ReferralCode, ForgotPassword, RequestEmail, OTPUserCreate, UsersCreate, \
    ServiceDurationUpdate, ServiceUpdateStatus, ServiceDurationCreate, ServiceAllUpdate, ServiceUpdate, Message, \
    ChangePassword, AdminAvatar, OTPCreate, OTPVerify, ResetPassword, AdminEmail, ServiceCreate, DeleteLoccation, \
    UpdateLoccation, CreatePromotion, UpdatePromotion, CreateSlide, CreateBlog, UpdateBlog, DeleteSlides, UpdateSlide, \
    UpdateBlogStatus, SelectPromotionId, CustomerPromotionsCreate, CreateInvoice, \
    CreatePartner, CreateWallet, CreateWalletU, CreateDanhGia, Messageid
from upload.file_uploader import FileUploader
from utils import get_all_admin, get_all_users, get_db_location, generate_referral_code, get_one_admin, get_users, \
    get_select_service_duration, get_select_service, delete_otp_after_delay, random_id, create_jwt_token, \
    verify_jwt_token, get_admin, oauth2_scheme, token_blacklist, get_delete_location, get_select_slides, \
    get_select_promotion, get_delete_slide, get_select_blog, current_date, get_select_promotion_id, get_db_user, \
    get_partner, extract_indexes, get_weekday_string, get_partner_id, get_week_string, get_db_partner, get_all_partner
from mail.send_emailTemp import send_email_temp
from mail.cskh_email import send_cskh_email
import json
from typing import List
from starlette.responses import Response, JSONResponse
from datetime import datetime, timedelta
from fastapi import WebSocket, WebSocketDisconnect


def get_database():
    database = Database(DATABASE_URL)
    return database

# Kết nối đến cơ sở dữ liệu
engine = create_engine(DATABASE_URL)
Base.metadata.create_all(bind=engine)

# Tạo đối tượng SessionLocal để tương tác với cơ sở dữ liệu
SessionLocal = sessionmaker(autocommit=False, autoflush=False, bind=engine)
app = FastAPI(root_path="/api/v1")
UPLOAD_DIR = "assets/images/"
UPLOAD_DIR_DANH_GIA = "assets/danh_gia/"
if not os.path.exists(UPLOAD_DIR):
    os.makedirs(UPLOAD_DIR)

uploader_danh_gia = FileUploader(upload_dir=UPLOAD_DIR_DANH_GIA)
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],  # Điều chỉnh lại để chỉ cho phép các nguồn cụ thể nếu cần
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)
clients: List[WebSocket] = []

#--------------------------------Admin-------------------------------------------------

# Đăng nhập
@app.post("/admin/login/")
async def login(form_data: dict, db: Session = Depends(get_database)):

    username = form_data["username"]
    password = form_data["password"]

    # Lấy thông tin người dùng từ cơ sở dữ liệu
    admin = await get_admin(db, username)


    # Kiểm tra thông tin đăng nhập
    if admin is None or admin["username"] != username:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail=-1,
            headers={"WWW-Authenticate": "Bearer"},
        )
    
    #kiểm tra mật khẩu
    if admin is None or admin["password"] != password:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail=-2,
            headers={"WWW-Authenticate": "Bearer"},
        )
    #kiểm tra trạng thái
    if admin is None or admin["status"] != 1:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail=-3,
            headers={"WWW-Authenticate": "Bearer"},
        )


    # Tạo JWT token
    token_data = {"sub": admin["username"], "role": admin["role"]}
    token = create_jwt_token(token_data)

    # Trả về token
    return {"access_token": token, "token_type": "bearer"}

# Endpoint để xác minh token
@app.post("/verify-token/")

async def verify_token(token: str = Depends(verify_jwt_token)):
    return {"status": "OK", "predictions": token}

# Endpoint đăng xuất
@app.post("/logout/", response_model=Message)
async def logout(token: str = Depends(oauth2_scheme)):
    # Thêm token vào danh sách đen khi đăng xuất
    token_blacklist.add(token)
    return Message(detail=0)

# Đổi mật khẩu người dùng
@app.put("/admin/change-password/", response_model=Message)
async def change_password(change_password: ChangePassword, current_user: dict = Depends(verify_jwt_token), db: Session = Depends(get_database)):
    # Lấy thông tin người dùng từ cơ sở dữ liệu
    user = await get_admin(db, current_user["sub"])
    print(user['password'])
    # Kiểm tra mật khẩu cũ
    if user['password'] != change_password.old_password:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail=-1,
        )
    
    # Kiểm tra trùng mật khẩu
    if change_password.new_password != change_password.enter_the_password:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail=-2,
        )
    update_query = update(Admin).where(Admin.id == user['id']).values(
            password=change_password.new_password)
    await db.execute(update_query)

    return Message(detail=0)

# Đổi avatar
@app.put("/admin/update-admin-avatar/", response_model=Message)
async def update_users_admin(update_user: AdminAvatar, current_user: dict = Depends(verify_jwt_token), db: Session = Depends(get_database)):
    # Lấy thông tin người dùng từ cơ sở dữ liệu
    admin = await get_admin(db, current_user["sub"])
    update_avatar_admin = AdminAvatar(**update_user.dict())

    update_query = update(Admin).where(Admin.id == admin['id']).values(
        image=update_avatar_admin.image,
        phonenumber= update_avatar_admin.phonenumber
    )
    await db.execute(update_query)

    return Message( detail = 0)

# yêu cầu OTP
@app.post("/admin/request-otp/",response_model=Message)
async def request_otp(otp_data: OTPCreate, background_tasks: BackgroundTasks, db: Session = Depends(get_database)):

    query = select(OTP).where(OTP.email == otp_data.email)
    otb_old = await db.fetch_one(query)
    
    if otb_old:
        delete_query = OTP.__table__.delete().where(OTP.email == otp_data.email)
        await db.execute(delete_query)
    
    query = select(Admin).where(Admin.email == otp_data.email)
    user = await db.fetch_one(query)
    if user:
        # Tạo và lưu OTP
        id = "OTB-"+ random_id()
        otp_code = str(random_id())

        new_otp_data = OTP(id=id, code=otp_code, **otp_data.dict())

        async with db.transaction():
            await db.execute(OTP.__table__.insert().values(
                id=new_otp_data.id,
                email=new_otp_data.email,
                code= otp_code,
            ))
        
        content = f"Xin chào {user['name']}!\n\nMã của bạn là {otp_code}\n\nNhóm,\n3Clean"
        title = f"Mã của bạn - {otp_code}"
        send_email_temp(new_otp_data.email, content, title)

        background_tasks.add_task(delete_otp_after_delay, new_otp_data.email, db)

        return Message(detail=0)
    raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail=-1)

@app.post("/request-otp-new-email/",response_model=Message)
async def request_otp_new_email(otp_data: OTPCreate, background_tasks: BackgroundTasks,current_user: dict = Depends(verify_jwt_token), db: Session = Depends(get_database)):
    
    user = await get_admin(db, current_user["sub"])
    query = select(OTP).where(OTP.email == otp_data.email)
    otb_old = await db.fetch_one(query)
    
    if otb_old:
        # Delete existing OTP data for the email
        delete_query = OTP.__table__.delete().where(OTP.email == otp_data.email)
        await db.execute(delete_query)
    
    id = "OTB-"+ random_id()
    otp_code = str(random_id())

    new_otp_data = OTP(id=id, code=otp_code, **otp_data.dict())

    async with db.transaction():
        await db.execute(OTP.__table__.insert().values(
            id=new_otp_data.id,
            email=new_otp_data.email,
            code= otp_code,
        ))
    content = f"Xin chào {user['name']}!\n\nMã của bạn là {otp_code}\n\nNhóm,\n3Clean"
    title = f"Mã của bạn - {otp_code}"
    send_email_temp(new_otp_data.email, content, title)

    background_tasks.add_task(delete_otp_after_delay, new_otp_data.email, db)

    return Message(detail=0)

# Đường dẫn để xác minh OTP
@app.post("/verify-otp/",response_model=Message)
async def verify_otp(otp_data: OTPVerify, db: Session = Depends(get_database)):

    query = select(OTP).where(OTP.email == otp_data.email)
    otp_old = await db.fetch_one(query)
    if otp_old and otp_old['code'] == otp_data.otp:
        # OTP hợp lệ
        return Message(detail=0)
    
    raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail=-1)

# Đường dẫn để xác minh OTP
@app.put("/admin/admin-update-email/",response_model=Message)
async def admin_update_email(admin_email: AdminEmail, current_user: dict = Depends(verify_jwt_token), db: Session = Depends(get_database)):

    user = await get_admin(db, current_user["sub"])
    
    update_email = AdminEmail(**admin_email.dict())
    
    update_query = update(Admin).where(Admin.id == user['id']).values(
            email=update_email.email)
    await db.execute(update_query)

    return Message(detail=0)

@app.post("/admin/reset-password/",response_model=Message)
async def reset_password(form_data: ResetPassword ,db: Session = Depends(get_database),):

    otp_update_query = update(Admin).where(Admin.email == form_data.email).values(password=form_data.new_password)
    await db.execute(otp_update_query)

    return Message(detail=0)

@app.put("/admin/update-status-partner/",response_model=Message)
async def update_status_partner(id: str, status: int, email: str, name: str, nameAD: str, db: Session = Depends(get_database)):
    otp_update_query = update(Partner).where(Partner.id == id).values(ban=status)
    await db.execute(otp_update_query)
    current_datetime = datetime.now()
    if status == 1:
        content = f"Xin chào {name}!\n\nTài khoản đối tác của bạn đã bị khóa kể từ {current_datetime}.\nMọi thắc mắc vui lòng liên hệ chăm sóc khách hàng.\n\nQuản trị viên: {nameAD}\n\nNhóm,\n3Clean"
        title = f"Thông báo khóa tài khoản"
    else:
        content = f"Xin chào {name}!\n\nTài khoản đối tác của bạn đã mở khóa kể từ {current_datetime} và đã có thể hoạt động.\nMọi thắc mắc vui lòng liên hệ chăm sóc khách hàng.\n\nQuản trị viên: {nameAD}\n\nNhóm,\n3Clean"
        title = f"Thông báo mở tài khoản"
    send_email_temp(email, content, title)
    return Message(detail=0)

# Thông tin admin
@app.get("/admin/select-admin-information/")
async def select_admin_information(current_user: dict = Depends(verify_jwt_token), db: Session = Depends(get_database)):
    # Lấy thông tin người dùng từ cơ sở dữ liệu
    admin = await get_admin(db, current_user["sub"])
    
    # Trả về dữ liệu bảo vệ
    return {"admin_info": admin}

@app.get("/admin/select-admin/")
async def select_admin(id:str, db: Session = Depends(get_database)):
    
    rows = await get_one_admin(db, id)

    # Tạo một từ điển chứa dữ liệu trả về
    response_data = {"admin": rows, "status": "OK"}

    return response_data

@app.get("/admin/select-all-admin/")
async def select_all_admin(db: Session = Depends(get_database)):
    # Lấy thông tin người dùng từ cơ sở dữ liệu
    rows = await get_all_admin(db)
    
    # Trả về dữ liệu bảo vệ
    admin = [dict(row) for row in rows]

    # Tạo một từ điển chứa dữ liệu trả về
    response_data = {"admin": admin, "status": "OK"}

    return JSONResponse(content=response_data, media_type="application/json; charset=UTF-8")

@app.post("/admin/create-admin/", response_model=Message)
async def create_admin(add_admin: CreateAdmin, current_user: dict = Depends(verify_jwt_token),db: Session = Depends(get_database)):
    db_admin = Admin(**add_admin.dict())
    current_datetime = datetime.now()
    admin = await get_admin(db, current_user["sub"])
    async with db.transaction():
        await db.execute(Admin.__table__.insert().values(
            id=db_admin.id,
            id_admin=admin['id'],
            username=db_admin.username,
            password=db_admin.password,
            email=db_admin.email,
            phonenumber=db_admin.phonenumber,
            name=db_admin.name,
            sex=db_admin.sex,
            datebirth=db_admin.datebirth,
            image=db_admin.image,
            permanent_address=db_admin.permanent_address,
            temporary_residence_address=db_admin.temporary_residence_address,
            position=db_admin.position,
            joiningdate=current_datetime,
            role=db_admin.role,
            status=1
        ))

    return Message(detail=0)

@app.put("/admin/update-admin/", response_model=Message)
async def update_admin(add_admin: CreateAdmin, current_user: dict = Depends(verify_jwt_token),db: Session = Depends(get_database)):
    db_admin = Admin(**add_admin.dict())
    admin = await get_admin(db, current_user["sub"])
    update_query = update(Admin).where(Admin.id == db_admin.id).values(
            id_admin=admin['id'],
            username=db_admin.username,
            password=db_admin.password,
            email=db_admin.email,
            phonenumber=db_admin.phonenumber,
            name=db_admin.name,
            sex=db_admin.sex,
            datebirth=db_admin.datebirth,
            image=db_admin.image,
            permanent_address=db_admin.permanent_address,
            temporary_residence_address=db_admin.temporary_residence_address,
            position=db_admin.position,
            role=db_admin.role)
    await db.execute(update_query)
    

    return Message(detail=0)

@app.put("/admin/update-status-admin/", response_model=Message)
async def update_status_admin(id: str, status: int, current_user: dict = Depends(verify_jwt_token),db: Session = Depends(get_database)):
    admin = await get_admin(db, current_user["sub"])
    update_query = update(Admin).where(Admin.id == id).values(
            id_admin=admin['id'],
            status=status)
    await db.execute(update_query)
    

    return Message(detail=0)

#---------------------------Quản lý tác vụ-------------------------------------------------

# Tạo dịch vụ
@app.post("/admin/create-service/", response_model=Message)
async def create_service(add_service: ServiceCreate, current_user: dict = Depends(verify_jwt_token),db: Session = Depends(get_database)):
    db_service = Service(**add_service.dict())

    admin = await get_admin(db, current_user["sub"])
    print(db_service.id)
    async with db.transaction():
        await db.execute(Service.__table__.insert().values(
            id=db_service.id,
            id_admin=admin['id'],
            name= db_service.name,
            icon= db_service.icon,
            label=db_service.label,
            status= db_service.status
        ))

    return Message(detail=0)

@app.get("/admin/select-service/")
async def select_service(db: Session = Depends(get_database)):

    db_select = await get_select_service(db)

    return {"service":db_select}

# Update dịch vụ
@app.put("/admin/update-service/",response_model=Message)
async def update_service(service_update: ServiceUpdate, db: Session = Depends(get_database)):
    
    _update = Service(**service_update.dict())
    print(_update.status)
    update_query = update(Service).where(Service.id == _update.id).values(status=_update.status)
    await db.execute(update_query)

    return Message(detail=0)

# Sửa dịch vụ
@app.put("/admin/update-all-service/",response_model=Message)
async def update_all_service(service_update: ServiceAllUpdate,current_user: dict = Depends(verify_jwt_token), db: Session = Depends(get_database)):
    
    _update = Service(**service_update.dict())
    admin = await get_admin(db, current_user["sub"])
    update_query = update(Service).where(Service.id == _update.id).values(
            name=_update.name,
            icon= _update.icon,
            id_admin=admin['id']
            )
    await db.execute(update_query)

    return Message(detail=0)

#---------------------------Quản lý Thời luọng-------------------------------------------------

# Tạo Thời lượng
@app.post("/admin/create-service-duration/", response_model=Message)
async def create_service_duration(add_service_duration: ServiceDurationCreate, current_user: dict = Depends(verify_jwt_token),db: Session = Depends(get_database)):
    
    id = "TL-" + str(random_id())
    db_service_duration = ServiceDurationCreate(id=id, **add_service_duration.dict())
    admin = await get_admin(db, current_user["sub"])
    async with db.transaction():
        await db.execute(ServiceDuration.__table__.insert().values(
            id=id,
            id_admin=admin['id'],
            time= db_service_duration.time,
            acreage= db_service_duration.acreage,
            room= db_service_duration.room,
            money= db_service_duration.money,
            status= db_service_duration.status
        ))

    return Message(detail=0)

@app.get("/admin/select-service-duration/")
async def select_service_duration(db: Session = Depends(get_database)):

    db_select = await get_select_service_duration(db)

    return {"service_duration":db_select,"status":"OK"}

# Update trạng thái thời lượng
@app.put("/admin/update-status-service-duration/",response_model=Message)
async def update_status_service_duration(service_duration_update: ServiceUpdateStatus, db: Session = Depends(get_database)):
    
    _update = Service(**service_duration_update.dict())
    
    update_query = update(ServiceDuration).where(ServiceDuration.id == _update.id).values(
            status=_update.status)
    await db.execute(update_query)

    return Message(detail=0)

# Sửa thời lượng
@app.put("/admin/update-service-duration/",response_model=Message)
async def update_service_duration(service_duration_update: ServiceDurationUpdate, current_user: dict = Depends(verify_jwt_token), db: Session = Depends(get_database)):
    
    _update = ServiceDurationUpdate(**service_duration_update.dict())
    admin = await get_admin(db, current_user["sub"])
    update_query = update(ServiceDuration).where(ServiceDuration.id == _update.id).values(
            time= _update.time,
            acreage= _update.acreage,
            room= _update.room,
            money= _update.money,
            id_admin=admin['id']
            )
    await db.execute(update_query)

    return Message(detail=0)




#--------------------------Blog-------------------------
@app.post("/admin/create-blog/", response_model=Message)
async def create_blog(add_blog: CreateBlog,current_user: dict = Depends(verify_jwt_token), db: Session = Depends(get_database)):

    db_blog = CreateBlog(**add_blog.dict())
    user = await get_admin(db, current_user["sub"])
    async with db.transaction():
        await db.execute(Blog.__table__.insert().values(
            id=db_blog.id,
            imageUrl=db_blog.imageUrl,
            newsUrl=db_blog.newsUrl,
            title=db_blog.title,
            content=db_blog.content,
            date=current_date,
            status=1,
            id_admin=user['id']
        ))

    return Message(detail=0)

@app.get("/admin/select-blog/")
async def select_blog(db: Session = Depends(get_database)):

    db_select = await get_select_blog(db)

    return {"blogs":db_select}

# Update blog
@app.put("/admin/update-blog/", response_model=Message)
async def update_blog(blog_update: UpdateBlog, db: Session = Depends(get_database)):

    _update = UpdateBlog(**blog_update.dict())

    update_query = update(Blog).where(Blog.id == _update.id).values(
        imageUrl=_update.imageUrl,
        newsUrl=_update.newsUrl,
        title=_update.title,
        content=_update.content
        )
    await db.execute(update_query)

    return Message(detail=0)

# Update blog status
@app.put("/admin/update-blog-status/", response_model=Message)
async def update_blog_status(blog_update: UpdateBlogStatus, db: Session = Depends(get_database)):
    stt = 0
    print(blog_update.id)
    print(blog_update.status)
    if blog_update.status == 1:
        stt = 0
    else:
        stt = 1
    update_query = update(Blog).where(Blog.id == blog_update.id).values(
        status=stt
        )
    await db.execute(update_query)

    return Message(detail=0)





# ----------------khuyến mãi-------------------------

@app.post("/admin/create-promotion/", response_model=Message)
async def create_promotion(add_promotion: CreatePromotion,current_user: dict = Depends(verify_jwt_token), db: Session = Depends(get_database)):

    db_promotion = Promotion(**add_promotion.dict())
    user = await get_admin(db, current_user["sub"])

    async with db.transaction():
        await db.execute(Promotion.__table__.insert().values(
            id=db_promotion.id,
            id_admin=user['id'],
            name=db_promotion.name,
            code=db_promotion.code,
            start_day=db_promotion.start_day,
            end_day=db_promotion.end_day,
            content=db_promotion.content,
            label=db_promotion.label,
            discount=db_promotion. discount,
            point=db_promotion.point
        ))

    return Message(detail=0)

@app.get("/admin/select-promotion/")
async def select_promotion(db: Session = Depends(get_database)):

    db_select = await get_select_promotion(db)

    return {"promotion":db_select}

@app.get("/select-promotion-id/")
async def select_promotion_id(select_id_promotion: SelectPromotionId,  db: Session = Depends(get_database)):
    select = SelectPromotionId(**select_id_promotion.dict())
    db_select = await get_select_promotion_id(db, select.id)

    return {"promotion":db_select}

# Update khuyến mãi
@app.put("/admin/update-promotion/", response_model=Message)
async def update_promotion(promotion_update: UpdatePromotion,current_user: dict = Depends(verify_jwt_token), db: Session = Depends(get_database)):

    _update = UpdatePromotion(**promotion_update.dict())
    user = await get_admin(db, current_user["sub"])
    update_query = update(Promotion).where(Promotion.id == _update.id).values(
        name=_update.name,
        code=_update.code,
        start_day=_update.start_day,
        end_day=_update.end_day,
        content=_update.content,
        label=_update.label,
        discount=_update.discount,
        point=_update.point,
        id_admin=user['id']
        )
    await db.execute(update_query)

    return Message(detail=0)





#-------------------------------------Slides-------------------------------------
@app.post("/admin/create-slides/", response_model=Message)
async def create_slide(add_promotion: CreateSlide,current_user: dict = Depends(verify_jwt_token), db: Session = Depends(get_database)):
    current_date = datetime.now().strftime("%d/%m/%Y")
    db_slide = CreateSlide(**add_promotion.dict())
    user = await get_admin(db, current_user["sub"])
    async with db.transaction():
        await db.execute(Slides.__table__.insert().values(
            id=db_slide.id,
            imageUrl=db_slide.imageUrl,
            newsUrl=db_slide.newsUrl,
            date=current_date,
            id_admin=user['id']
        ))

    return Message(detail=0)

@app.get("/admin/select-slides/")
async def select_slides(db: Session = Depends(get_database)):

    db_select = await get_select_slides(db)

    return {"slides":db_select}

@app.delete("/admin/delete-slides/")
async def delete_slide(delete_sl: DeleteSlides, db: Session = Depends(get_database)):

    await get_delete_slide(db, delete_sl.id)

    return {"detail": "OK"}

@app.put("/admin/update-slides/")
async def update_slide(update_sl: UpdateSlide,current_user: dict = Depends(verify_jwt_token), db: Session = Depends(get_database)):
    admin = await get_admin(db, current_user["sub"])
    update_slides = update(Slides).where(Slides.id == update_sl.id).values(
        imageUrl=update_sl.imageUrl,
        newsUrl=update_sl.newsUrl,
        id_admin=admin['id']
    )
    await  db.execute(update_slides)

    return {"detail": "OK"}

#----------------Đối tác----------------
@app.get("/admin/get-doi-tac/")
async def get_doi_tac(db: Session = Depends(get_database)):
    rows = await get_all_partner(db)

    # Chuyển đổi các dòng thành danh sách từ điển
    partner = [dict(row) for row in rows]

    # Tạo một từ điển chứa dữ liệu trả về
    response_data = {"partner": partner, "status": "OK"}

    return JSONResponse(content=response_data, media_type="application/json; charset=UTF-8")

@app.get("/admin/get-one-doi-tac/")
async def get_one_doi_tac(id: str, db: Session = Depends(get_database)):
    row = await get_partner_id(db, id)

    if row:
        # Chuyển đổi dòng dữ liệu thành một từ điển nếu có
        partner = dict(row)
        # Tạo một từ điển chứa dữ liệu trả về
        response_data = {"partner": partner, "status": "OK"}
    else:
        # Nếu không có dữ liệu, trả về thông báo lỗi
        response_data = {"status": "Error", "message": "Partner not found"}

    return JSONResponse(content=response_data, media_type="application/json; charset=UTF-8")

@app.get("/admin/get-doanh-thu-doi-tac-id", response_model=Message)
async def get_doanh_thu_doi_tac_id(id: str, start_date: str, end_date: str, db: Session = Depends(get_database)):
    
    sql_query = """
       SELECT 
    id.id,
    i.id_users,
    id.name_user,
    id.price,
    id.cancellation_time_completed
    FROM 
        partner p
    INNER JOIN 
        invoice_details id ON p.id = id.id_partner
    INNER JOIN 
        invoice i ON i.id = id.id_invoice
    WHERE
        id.order_status = 6
    AND
        p.id = :user_id
    AND
        id.cancellation_time_completed >= :start_date
    AND
        id.cancellation_time_completed <= :end_date
    ORDER BY 
        id.cancellation_time_completed DESC;
       """

    # Execute the SQL query
    filtered_data = await db.fetch_all(sql_query, values={"user_id": id,"start_date": start_date, "end_date": end_date})

    result_json = {
        'doi-tac-id': [
            {
                "id": item['id'],
                "id_users": item['id_users'],
                "name_user": item['name_user'],
                "price": item['price'],
                "date": item['cancellation_time_completed']
            }
            for item in filtered_data
        ],
        'status':'OK'
    }

    return JSONResponse(content=result_json, media_type="application/json; charset=UTF-8")

@app.get("/admin/get-danh-gia-doi-tac-id", response_model=Message)
async def get_danh_gia_doi_tac_id(id: str, start_date: str, end_date: str, db: Session = Depends(get_database)):
    
    sql_query = """
       SELECT 
        e.id,
        e.id_user,
        u.name,
        e.star,
        e.content,
        e.date
    FROM 
        partner p
    INNER JOIN 
        evaluate e ON p.id = e.id_partner
    INNER JOIN 
        users u ON u.id = e.id_user
    WHERE
        p.id = :user_id
    AND
        e.date >= :start_date
    AND
        e.date <= :end_date
    ORDER BY 
        e.date DESC;
       """

    # Execute the SQL query
    filtered_data = await db.fetch_all(sql_query, values={"user_id": id,"start_date": start_date, "end_date": end_date})

    result_json = {
        'doi-tac-id': [
            {
                "id": item['id'],
                "id_user": item['id_user'],
                "name": item['name'],
                "star": item['star'],
                "content": item['content'],
                "date": item['date']
            }
            for item in filtered_data
        ],
        'status':'OK'
    }

    return JSONResponse(content=result_json, media_type="application/json; charset=UTF-8")

@app.get("/admin/get-hoa-don-all", response_model=Message)
async def get_hoa_don_all(id: str, start_date: str, end_date: str, db: Session = Depends(get_database)):
    
    sql_query = """
       SELECT 
    id.id,
    i.id_users,
    i.label,
    id.name_user,
    id.posting_time,
    id.working_day, 
    id.work_time, 
    id.room_area,
    id.location, 
    id.location2,
    id.price, 
    id.payment_methods,
    id.premium_service,
    id.pet_note, 
    id.employee_note,
    id.order_status,
    id.cancellation_time_completed,
    id.cancel_job,
    id.reason_cancellation,
    id.cancellation_fee
FROM 
    partner p
INNER JOIN 
    invoice_details id ON p.id = id.id_partner
INNER JOIN
    invoice i ON id.id_invoice = i.id
WHERE
    id.id_partner = :user_id
    AND id.cancellation_time_completed >= :start_date
    AND id.cancellation_time_completed <= :end_date
ORDER BY 
    id.cancellation_time_completed DESC;

       """

    # Execute the SQL query
    filtered_data = await db.fetch_all(sql_query, values={"user_id": id,"start_date": start_date, "end_date": end_date})

    result_json = {
        'hoa-don-doi-tac': [
            {
                "id": item['id'],
                "id_users": item['id_users'],
                "label":item['label'],
                "name": item['name_user'],
                "posting_time": item['posting_time'],
                "working_day": item['working_day'],
                "work_time": item['work_time'],
                "room_area": item['room_area'],
                "location": item['location'],
                "location2": item['location2'],
                "price": item['price'],
                "payment_methods": item['payment_methods'],
                "premium_service": item['premium_service'],
                "pet_note": item['pet_note'],
                "employee_note": item['employee_note'],
                "order_status": item['order_status'],
                "status": item['order_status'],
                "cancellation_time_completed": item['cancellation_time_completed'],
                "cancel_job": item['cancel_job'],
                "reason_cancellation": item['reason_cancellation'],
                "cancellation_fee": item['cancellation_fee']
            }
            for item in filtered_data
        ],
        'status':'OK'
    }

    return JSONResponse(content=result_json, media_type="application/json; charset=UTF-8")


@app.get("/admin/get-khach-hang/")
async def get_khach_hang(db: Session = Depends(get_database)):
    rows = await get_all_users(db)

    # Chuyển đổi các dòng thành danh sách từ điển
    partner = [dict(row) for row in rows]

    # Tạo một từ điển chứa dữ liệu trả về
    response_data = {"users": partner, "status": "OK"}

    return JSONResponse(content=response_data, media_type="application/json; charset=UTF-8")


@app.get("/admin/get-khach-hang-id")
async def get_khach_hang_id(id:str, db: Session = Depends(get_database)):
    rows = await get_db_user(db, id)

    # Chuyển đổi các dòng thành danh sách từ điển

    user = [dict(row) for row in rows]

    # Tạo một từ điển chứa dữ liệu trả về
    response_data = {"users": user, "status": "OK"}

    return JSONResponse(content=response_data, media_type="application/json; charset=UTF-8")


@app.put("/admin/update-status-user",response_model=Message)
async def update_status_user(id: str, status: int, email: str, name: str, nameAD: str, db: Session = Depends(get_database)):
    otp_update_query = update(Users).where(Users.id == id).values(ban=status)
    await db.execute(otp_update_query)
    current_datetime = datetime.now()
    if status == 1:
        content = f"Xin chào {name}!\n\nTài khoản đối tác của bạn đã bị khóa kể từ {current_datetime}.\nMọi thắc mắc vui lòng liên hệ chăm sóc khách hàng.\n\nQuản trị viên: {nameAD}\n\nNhóm,\n3Clean"
        title = f"Thông báo khóa tài khoản"
    else:
        content = f"Xin chào {name}!\n\nTài khoản đối tác của bạn đã mở khóa kể từ {current_datetime} và đã có thể hoạt động.\nMọi thắc mắc vui lòng liên hệ chăm sóc khách hàng.\n\nQuản trị viên: {nameAD}\n\nNhóm,\n3Clean"
        title = f"Thông báo mở tài khoản"
    send_email_temp(email, content, title)
    return Message(detail=0)


@app.get("/admin/get-hoa-don-cho-lam-kh", response_model=Message)
async def get_hoa_don_cho_lam_kh(id: str, start_date: str, end_date: str, db: Session = Depends(get_database)):
    
    sql_query = """
        SELECT 
    id.id,
    id.id_partner,
    i.label,
    id.name_user,
    id.posting_time,
    id.working_day, 
    id.work_time, 
    id.room_area,
    id.location, 
    id.location2,
    id.price, 
    id.payment_methods,
    id.premium_service,
    id.pet_note, 
    id.employee_note,
    id.order_status,
    id.cancellation_time_completed,
    id.cancel_job,
    id.reason_cancellation,
    id.cancellation_fee
FROM 
    invoice i
INNER JOIN 
    invoice_details id ON id.id_invoice = i.id
WHERE
    i.id_users = :user_id
    AND id.posting_time >= :start_date
    AND id.posting_time <= :end_date
ORDER BY 
    id.posting_time DESC;

       """

    # Execute the SQL query
    filtered_data = await db.fetch_all(sql_query, values={"user_id": id,"start_date": start_date, "end_date": end_date})

    result_json = {
        'hoa-don-khach-hang': [
            {
                "id": item['id'],
                "id_partner": item['id_partner'],
                "label":item['label'],
                "name": item['name_user'],
                "posting_time": item['posting_time'],
                "working_day": item['working_day'],
                "work_time": item['work_time'],
                "room_area": item['room_area'],
                "location": item['location'],
                "location2": item['location2'],
                "price": item['price'],
                "payment_methods": item['payment_methods'],
                "premium_service": item['premium_service'],
                "pet_note": item['pet_note'],
                "employee_note": item['employee_note'],
                "order_status":  item['order_status'],
                "status": item['order_status'],
                "cancellation_time_completed": item['cancellation_time_completed'],
                "cancel_job": item['cancel_job'],
                "reason_cancellation": item['reason_cancellation'],
                "cancellation_fee": item['cancellation_fee']
            }
            for item in filtered_data
        ],
        'status':'OK'
    }

    return JSONResponse(content=result_json, media_type="application/json; charset=UTF-8")

@app.get("/admin/get-hoa-don-lap-lai", response_model=Message)
async def get_hoa_don_lap_lai(id: str, start_date: str, end_date: str, db: Session = Depends(get_database)):
    
    sql_query = """
              SELECT 
    id.id AS idId,
    i.id AS idI,
    id.id_partner,
    i.repeat_state,
    i.cancel_repeat,
    i.repeat,
    i.duration,
    i.removal_date,
    i.label,
    id.name_user,
    id.posting_time,
    id.working_day, 
    id.work_time, 
    id.room_area,
    id.location, 
    id.location2,
    id.price, 
    id.payment_methods,
    id.premium_service,
    id.pet_note, 
    id.employee_note,
    id.order_status,
    id.cancellation_time_completed,
    id.cancel_job,
    id.reason_cancellation,
    id.cancellation_fee
    
FROM 
    invoice i
INNER JOIN 
    invoice_details id ON id.id_invoice = i.id
WHERE
    i.id_users = :user_id
    AND i.repeat_state = 1
    AND (i.duration IS NULL OR i.duration = "")
    AND id.posting_time = (
        SELECT MIN(posting_time) 
        FROM invoice_details 
        WHERE id_invoice = i.id
    )
    AND id.posting_time >= :start_date
    AND id.posting_time <= :end_date
    ORDER BY 
    id.posting_time DESC;
       """

    # Execute the SQL query
    filtered_data = await db.fetch_all(sql_query, values={"user_id": id,"start_date": start_date, "end_date": end_date})

    result_json = {
        'hoa-don-khach-hang': [
            {
                "idId": item['idId'],
                "idI": item['idI'],
                "id_partner": item['id_partner'],
                "cancel_repeat": item['cancel_repeat'],
                "repeat_state": item['repeat_state'],
                "repeat":item['repeat'],
                "duration":item['duration'],
                "removal_date":item['removal_date'],
                "label":item['label'],
                "name": item['name_user'],
                "posting_time": item['posting_time'],
                "working_day": item['working_day'],
                "work_time": item['work_time'],
                "room_area": item['room_area'],
                "location": item['location'],
                "location2": item['location2'],
                "price": item['price'],
                "payment_methods": item['payment_methods'],
                "premium_service": item['premium_service'],
                "pet_note": item['pet_note'],
                "employee_note": item['employee_note'],
                "order_status":  item['order_status'],
                "status": item['order_status'],
                "cancellation_time_completed": item['cancellation_time_completed'],
                "cancel_job": item['cancel_job'],
                "reason_cancellation": item['reason_cancellation'],
                "cancellation_fee": item['cancellation_fee']
            }
            for item in filtered_data
        ],
        'status':'OK'
    }

    return JSONResponse(content=result_json, media_type="application/json; charset=UTF-8")

@app.get("/admin/get-hoa-don-theo-goi", response_model=Message)
async def get_hoa_don_theo_goi(id: str, start_date: str, end_date: str, db: Session = Depends(get_database)):
    
    sql_query = """
              SELECT 
    id.id AS idId,
    i.id AS idI,
    id.id_partner,
    i.repeat_state,
    i.cancel_repeat,
    i.repeat,
    i.duration,
    i.removal_date,
    i.label,
    id.name_user,
    id.posting_time,
    id.working_day, 
    id.work_time, 
    id.room_area,
    id.location, 
    id.location2,
    id.price, 
    id.payment_methods,
    id.premium_service,
    id.pet_note, 
    id.employee_note,
    id.order_status,
    id.cancellation_time_completed,
    id.cancel_job,
    id.reason_cancellation,
    id.cancellation_fee
    
FROM 
    invoice i
INNER JOIN 
    invoice_details id ON id.id_invoice = i.id
WHERE
    i.id_users = :user_id
    AND i.repeat_state = 1
    AND i.duration IS NOT NULL
    AND i.duration != ""
    AND id.posting_time = (
        SELECT MIN(posting_time) 
        FROM invoice_details 
        WHERE id_invoice = i.id
    )
    AND id.posting_time >= :start_date
    AND id.posting_time <= :end_date
    ORDER BY 
    id.posting_time DESC;
       """

    # Execute the SQL query
    filtered_data = await db.fetch_all(sql_query, values={"user_id": id,"start_date": start_date, "end_date": end_date})

    result_json = {
        'hoa-don-khach-hang': [
            {
                "idId": item['idId'],
                "idI": item['idI'],
                "id_partner": item['id_partner'],
                "cancel_repeat": item['cancel_repeat'],
                "repeat_state": item['repeat_state'],
                "repeat":item['repeat'],
                "duration":item['duration'],
                "removal_date":item['removal_date'],
                "label":item['label'],
                "name": item['name_user'],
                "posting_time": item['posting_time'],
                "working_day": item['working_day'],
                "work_time": item['work_time'],
                "room_area": item['room_area'],
                "location": item['location'],
                "location2": item['location2'],
                "price": item['price'],
                "payment_methods": item['payment_methods'],
                "premium_service": item['premium_service'],
                "pet_note": item['pet_note'],
                "employee_note": item['employee_note'],
                "order_status":  item['order_status'],
                "status": item['order_status'],
                "cancellation_time_completed": item['cancellation_time_completed'],
                "cancel_job": item['cancel_job'],
                "reason_cancellation": item['reason_cancellation'],
                "cancellation_fee": item['cancellation_fee']
            }
            for item in filtered_data
        ],
        'status':'OK'
    }

    return JSONResponse(content=result_json, media_type="application/json; charset=UTF-8")

@app.get("/admin/get-danh-gia-user", response_model=Message)
async def get_danh_gia_user(id: str,start_date: str, end_date: str, db: Session = Depends(get_database)):
    
    sql_query = """
        select 
 e.id,
 e.id_partner,
 p.name AS nameP,
 e.content,
 e.star,
 e.date
from 
evaluate e 
INNER JOIN partner p ON e.id_partner = p.id
where 
 id_user = :user_id
 AND
        e.date >= :start_date
    AND
        e.date <= :end_date
    ORDER BY 
    e.date DESC;
       """

    # Execute the SQL query
    filtered_data = await db.fetch_all(sql_query, values={"user_id": id,"start_date":start_date,"end_date":end_date})

    result_json = {
        'danh-gia': [
            {
                "id": item['id'],
                "id_partner": item['id_partner'],
                "nameP": item['nameP'],
                "content": item['content'],
                "star": item['star'],
                "date":item['date']
            }
            for item in filtered_data
        ],
        'status':'OK'
    }

    return JSONResponse(content=result_json, media_type="application/json; charset=UTF-8")


@app.get("/admin/get-hoa-don-cho-lam-bc", response_model=Message)
async def get_hoa_don_cho_lam_bc(start_date: str, end_date: str, db: Session = Depends(get_database)):
    
    sql_query = """
        SELECT 
    id.id,
    id.id_partner,
    i.label,
    id.name_user,
    id.posting_time,
    id.working_day, 
    id.work_time, 
    id.room_area,
    id.location, 
    id.location2,
    id.price, 
    id.payment_methods,
    id.premium_service,
    id.pet_note, 
    id.employee_note,
    id.order_status,
    id.cancellation_time_completed,
    id.cancel_job,
    id.reason_cancellation,
    id.cancellation_fee
FROM 
    invoice i
INNER JOIN 
    invoice_details id ON id.id_invoice = i.id
WHERE
    id.posting_time >= :start_date
    AND id.posting_time <= :end_date
ORDER BY 
    id.posting_time DESC;

       """

    # Execute the SQL query
    filtered_data = await db.fetch_all(sql_query, values={"start_date": start_date, "end_date": end_date})

    result_json = {
        'hoa-don-khach-hang': [
            {
                "id": item['id'],
                "id_partner": item['id_partner'],
                "label":item['label'],
                "name": item['name_user'],
                "posting_time": item['posting_time'],
                "working_day": item['working_day'],
                "work_time": item['work_time'],
                "room_area": item['room_area'],
                "location": item['location'],
                "location2": item['location2'],
                "price": item['price'],
                "payment_methods": item['payment_methods'],
                "premium_service": item['premium_service'],
                "pet_note": item['pet_note'],
                "employee_note": item['employee_note'],
                "order_status":  item['order_status'],
                "status": item['order_status'],
                "cancellation_time_completed": item['cancellation_time_completed'],
                "cancel_job": item['cancel_job'],
                "reason_cancellation": item['reason_cancellation'],
                "cancellation_fee": item['cancellation_fee']
            }
            for item in filtered_data
        ],
        'status':'OK'
    }

    return JSONResponse(content=result_json, media_type="application/json; charset=UTF-8")


@app.get("/admin/get-hoa-don-lap-lai-bc", response_model=Message)
async def get_hoa_don_lap_lai_bc(start_date: str, end_date: str, db: Session = Depends(get_database)):
    
    sql_query = """
              SELECT 
    id.id AS idId,
    i.id AS idI,
    id.id_partner,
    i.repeat_state,
    i.cancel_repeat,
    i.repeat,
    i.duration,
    i.removal_date,
    i.label,
    id.name_user,
    id.posting_time,
    id.working_day, 
    id.work_time, 
    id.room_area,
    id.location, 
    id.location2,
    id.price, 
    id.payment_methods,
    id.premium_service,
    id.pet_note, 
    id.employee_note,
    id.order_status,
    id.cancellation_time_completed,
    id.cancel_job,
    id.reason_cancellation,
    id.cancellation_fee
    
FROM 
    invoice i
INNER JOIN 
    invoice_details id ON id.id_invoice = i.id
WHERE
    i.repeat_state = 1
    AND (i.duration IS NULL OR i.duration = "")
    AND id.posting_time = (
        SELECT MIN(posting_time) 
        FROM invoice_details 
        WHERE id_invoice = i.id
    )
    AND id.posting_time >= :start_date
    AND id.posting_time <= :end_date
    ORDER BY 
    id.posting_time DESC;
       """

    # Execute the SQL query
    filtered_data = await db.fetch_all(sql_query, values={"start_date": start_date, "end_date": end_date})

    result_json = {
        'hoa-don-khach-hang': [
            {
                "idId": item['idId'],
                "idI": item['idI'],
                "id_partner": item['id_partner'],
                "cancel_repeat": item['cancel_repeat'],
                "repeat_state": item['repeat_state'],
                "repeat":item['repeat'],
                "duration":item['duration'],
                "removal_date":item['removal_date'],
                "label":item['label'],
                "name": item['name_user'],
                "posting_time": item['posting_time'],
                "working_day": item['working_day'],
                "work_time": item['work_time'],
                "room_area": item['room_area'],
                "location": item['location'],
                "location2": item['location2'],
                "price": item['price'],
                "payment_methods": item['payment_methods'],
                "premium_service": item['premium_service'],
                "pet_note": item['pet_note'],
                "employee_note": item['employee_note'],
                "order_status":  item['order_status'],
                "status": item['order_status'],
                "cancellation_time_completed": item['cancellation_time_completed'],
                "cancel_job": item['cancel_job'],
                "reason_cancellation": item['reason_cancellation'],
                "cancellation_fee": item['cancellation_fee']
            }
            for item in filtered_data
        ],
        'status':'OK'
    }

    return JSONResponse(content=result_json, media_type="application/json; charset=UTF-8")

@app.get("/admin/get-hoa-don-theo-goi-tg", response_model=Message)
async def get_hoa_don_theo_goi_tg(start_date: str, end_date: str, db: Session = Depends(get_database)):
    
    sql_query = """
              SELECT 
    id.id AS idId,
    i.id AS idI,
    id.id_partner,
    i.repeat_state,
    i.cancel_repeat,
    i.repeat,
    i.duration,
    i.removal_date,
    i.label,
    id.name_user,
    id.posting_time,
    id.working_day, 
    id.work_time, 
    id.room_area,
    id.location, 
    id.location2,
    id.price, 
    id.payment_methods,
    id.premium_service,
    id.pet_note, 
    id.employee_note,
    id.order_status,
    id.cancellation_time_completed,
    id.cancel_job,
    id.reason_cancellation,
    id.cancellation_fee
    
FROM 
    invoice i
INNER JOIN 
    invoice_details id ON id.id_invoice = i.id
WHERE
    i.repeat_state = 1
    AND i.duration IS NOT NULL
    AND i.duration != ""
    AND id.posting_time = (
        SELECT MIN(posting_time) 
        FROM invoice_details 
        WHERE id_invoice = i.id
    )
    AND id.posting_time >= :start_date
    AND id.posting_time <= :end_date
    ORDER BY 
    id.posting_time DESC;
       """

    # Execute the SQL query
    filtered_data = await db.fetch_all(sql_query, values={"start_date": start_date, "end_date": end_date})

    result_json = {
        'hoa-don-khach-hang': [
            {
                "idId": item['idId'],
                "idI": item['idI'],
                "id_partner": item['id_partner'],
                "cancel_repeat": item['cancel_repeat'],
                "repeat_state": item['repeat_state'],
                "repeat":item['repeat'],
                "duration":item['duration'],
                "removal_date":item['removal_date'],
                "label":item['label'],
                "name": item['name_user'],
                "posting_time": item['posting_time'],
                "working_day": item['working_day'],
                "work_time": item['work_time'],
                "room_area": item['room_area'],
                "location": item['location'],
                "location2": item['location2'],
                "price": item['price'],
                "payment_methods": item['payment_methods'],
                "premium_service": item['premium_service'],
                "pet_note": item['pet_note'],
                "employee_note": item['employee_note'],
                "order_status":  item['order_status'],
                "status": item['order_status'],
                "cancellation_time_completed": item['cancellation_time_completed'],
                "cancel_job": item['cancel_job'],
                "reason_cancellation": item['reason_cancellation'],
                "cancellation_fee": item['cancellation_fee']
            }
            for item in filtered_data
        ],
        'status':'OK'
    }

    return JSONResponse(content=result_json, media_type="application/json; charset=UTF-8")

@app.get("/admin/get-doanh-thu-bc", response_model=Message)
async def get_doanh_thu_bc(start_date: str, end_date: str, db: Session = Depends(get_database)):
    
    sql_query = """
       SELECT 
    id.id,
    i.id_users,
    id.name_user,
    id.id_partner,
    p.name AS nameP,
    id.price,
    id.cancellation_time_completed
    FROM 
        partner p
    INNER JOIN 
        invoice_details id ON p.id = id.id_partner
    INNER JOIN 
        invoice i ON i.id = id.id_invoice
    WHERE
        id.order_status = 6
    AND
        id.cancellation_time_completed >= :start_date
    AND
        id.cancellation_time_completed <= :end_date
    ORDER BY 
        id.cancellation_time_completed DESC;
       """

    # Execute the SQL query
    filtered_data = await db.fetch_all(sql_query, values={"start_date": start_date, "end_date": end_date})

    result_json = {
        'doanh-thu': [
            {
                "id": item['id'],
                "id_users": item['id_users'],
                "name_user": item['name_user'],
                "id_partner": item['id_partner'],
                "nameP": item['nameP'],
                "price": item['price'],
                "date": item['cancellation_time_completed']
            }
            for item in filtered_data
        ],
        'status':'OK'
    }

    return JSONResponse(content=result_json, media_type="application/json; charset=UTF-8")
#-----------Khách Hàng------------------

# Đăng nhập người dùng
@app.post("/login-user/")
async def login_user(form_data: dict, db: Session = Depends(get_database)):

    email = form_data["email"]
    password = form_data["password"]
    # Lấy thông tin người dùng từ cơ sở dữ liệu
    user = await get_users(db, email)
    # Kiểm tra thông tin đăng nhập
    if user is None or user["email"] != email:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail=-1,
            headers={"WWW-Authenticate": "Bearer"},
        )
    #kiểm tra mật khẩu
    if user is None or user["password"] != password:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail=-2,
            headers={"WWW-Authenticate": "Bearer"},
        )
    if user is None or user["ban"] != 0:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail=-3,
            headers={"WWW-Authenticate": "Bearer"},
        )
    # Tạo JWT token
    token_data = {"sub": user["email"], "id": user["id"]}
    token = create_jwt_token(token_data)

    # Trả về token
    return {"access_token": token, "token_type": "bearer"}


@app.get("/get-user/")
async def get_user(current_user: dict = Depends(verify_jwt_token), db: Session = Depends(get_database)):
    # Lấy thông tin người dùng hiện tại
    user = await get_users(db, current_user["sub"])

    rows = await get_db_user(db, user['id'])

    # Chuyển đổi các dòng thành danh sách từ điển

    user = [dict(row) for row in rows]

    # Tạo một từ điển chứa dữ liệu trả về
    response_data = {"user": user, "status": "OK"}

    return JSONResponse(content=response_data, media_type="application/json; charset=UTF-8")

# yêu cầu OTP
@app.post("/request-otp-user/",response_model=Message)
async def request_otp_user(otp_data: OTPUserCreate, background_tasks: BackgroundTasks, db: Session = Depends(get_database)):
    
    name = ""
    if otp_data.name == "":
        query = select(Users).where(Users.email == otp_data.email)
        otb_old = await db.fetch_one(query)
        name = otb_old['name']
    else:
        name = otp_data.name

    query = select(OTP).where(OTP.email == otp_data.email)
    otb_old = await db.fetch_one(query)
    # Kiểm tra nếu otb_old không rỗng
    if otb_old:
        delete_query = OTP.__table__.delete().where(OTP.email == otp_data.email)
        await db.execute(delete_query)

    # Tạo và lưu OTP
    id = "OTB-"+ random_id()
    otp_code = str(random_id())

    new_otp_data = OTP(id=id, code=otp_code, **otp_data.dict())
    
    async with db.transaction():
        await db.execute(OTP.__table__.insert().values(
            id=new_otp_data.id,
            email=new_otp_data.email,
            code= otp_code,
            name=name
        ))
    content = f"Xin chào {name}!\n\nMã của bạn là {otp_code}\n\nNhóm,\n3Clean"
    title = f"Mã của bạn - {otp_code}"
    send_email_temp(new_otp_data.email, content, title)

    background_tasks.add_task(delete_otp_after_delay, new_otp_data.email, db)

    return Message(detail=0)

@app.post("/create-users/", response_model=Message)
async def create_user(add_users: UsersCreate, db: Session = Depends(get_database)):
    id = "KH-" + random_id()
    db_user = Users(id=id,**add_users.dict())

    code = generate_referral_code()

    # Kiểm tra nếu referralCode là None, gán giá trị mặc định
    referral_code = add_users.referralCode if add_users.referralCode is not None else ""

    async with db.transaction():
        await db.execute(Users.__table__.insert().values(
            id=id,
            password=db_user.password,
            phoneNumber=db_user.phoneNumber,
            email=db_user.email,
            name=db_user.name,
            image="",
            money=0,
            g_points=0,
            sex=db_user.sex,
            datebirth=db_user.datebirth,
            ban=0,
            yourReferralCode=code,
            referralCode=referral_code
        ))

    return Message(detail=0)

#check mã giới thiệu
@app.post("/referral-code/",response_model=Message)
async def referral_code(check_eferral_ode: ReferralCode, db: Session = Depends(get_database)):

    query = select(Users).where(Users.yourReferralCode == check_eferral_ode.referralCode)
    otb_old = await db.fetch_one(query)

    # Kiểm tra nếu otb_old không rỗng
    if otb_old and  otb_old['yourReferralCode'] == check_eferral_ode.referralCode:
        return Message(detail=0)
    raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail=-1)

#kiểm tra email có tồn tại không
@app.post("/request-email/",response_model=Message)
async def request_email(otp_data: RequestEmail, db: Session = Depends(get_database)):

    query = select(Users).where(Users.email == otp_data.email)
    otb_old = await db.fetch_one(query)

    # Kiểm tra nếu otb_old không rỗng
    if otb_old:
        return Message(detail=0)
    raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail=-1)

# Quên mật khẩu người dùng
@app.put("/forgot-password/", response_model=Message)
async def forgot_password(update_forgot_password: ForgotPassword, db: Session = Depends(get_database)):
    
    update_query = update(Users).where(Users.email == update_forgot_password.email).values(
            password=update_forgot_password.newPassword)
    await db.execute(update_query)

    return Message(detail=0)

#thêm mã khuyến mãi khách hàng
@app.post("/create-customer-promotions/", response_model=Message)
async def create_customer_promotions(add_create_promotions: CustomerPromotionsCreate,current_user: dict = Depends(verify_jwt_token),  db: Session = Depends(get_database)):
    id = "CP-" + random_id()

    status = 1
    user = await get_users(db, current_user["sub"])


    db_promotions = CustomerPromotionsCreate(**add_create_promotions.dict())

    async with db.transaction():
        pass
    await db.execute(CustomerPromotions.__table__.insert().values(
        id=id,
        id_users=user['id'],
        id_promotion=db_promotions.id,
        status=status

    ))

    return Message(detail=0)

#kiểm tra khuyến mãi
@app.post("/check-customer-promotions/", response_model=Message)
async def check_customer_promotions(add_check_promotions: CustomerPromotionsCreate,current_user: dict = Depends(verify_jwt_token),  db: Session = Depends(get_database)):
    user = await get_users(db, current_user["sub"])

    db_promotions = CustomerPromotionsCreate(**add_check_promotions.dict())

    query = CustomerPromotions.__table__.select().where((CustomerPromotions.id_users == user['id']) & (CustomerPromotions.id_promotion == db_promotions.id))
    service = await db.fetch_one(query)
    if service:
        return Message(detail=0)
    return Message(detail=-1)

@app.post("/post-danhgia/", response_model=Message)
async def post_danhgia(idP: str,idID:str, sao:int, note:str, files: List[UploadFile] = File(...),current_user: dict = Depends(verify_jwt_token),  db: Session = Depends(get_database)):
    user = await get_users(db, current_user["sub"])
    id = "EV-" + random_id()
    db_partner = await  get_partner_id(db, idP)

    current_datetime = datetime.now()

    image_paths = []
    for file in files:
        file_path = await uploader_danh_gia.upload_file(file)
        image_paths.append(file_path)
    image_urls = ",".join([image['file_path'] for image in image_paths])
    if(sao == 1):
        motSao = db_partner['one_star'] + 1
        update_queryy = update(Partner).where(Partner.id == idP).values(one_star=motSao)
        await db.execute(update_queryy)
    elif (sao == 2):
        haiSao = db_partner['two_star'] + 1
        update_queryy = update(Partner).where(Partner.id == idP).values(two_star=haiSao)
        await db.execute(update_queryy)
    elif (sao == 3):
        baSao = db_partner['three_star'] + 1
        update_queryy = update(Partner).where(Partner.id == idP).values(three_star=baSao)
        await db.execute(update_queryy)
    elif (sao == 4):
        bonSao = db_partner['four_star'] + 1
        update_queryy = update(Partner).where(Partner.id == idP).values(four_star=bonSao)
        await db.execute(update_queryy)
    elif (sao == 5):
        namSao = db_partner['five_star'] + 1
        update_queryy = update(Partner).where(Partner.id == idP).values(five_star=namSao)
        await db.execute(update_queryy)


    await db.execute(Evaluate.__table__.insert().values(
        id=id,
        id_partner=idP,
        id_user=user['id'],
        star=sao,
        content=note,
        date=current_datetime,
        image=image_urls
    ))

    update_queryy = update(InvoiceDetails).where(InvoiceDetails.id == idID).values(order_status=6)
    await db.execute(update_queryy)
    return Message(detail=0)
@app.get("/get-image/")
async def get_image(image_path: str):
    # Kiểm tra xem hình ảnh có tồn tại không
    full_path = os.path.join(image_path)
    print(full_path)
    if not os.path.exists(full_path):
        raise HTTPException(status_code=404, detail="Image not found")
    
    # Trả về hình ảnh
    return FileResponse(full_path)

@app.get("/get-customer-promotions/", response_model=Message)
async def get_customer_promotions(current_user: dict = Depends(verify_jwt_token),  db: Session = Depends(get_database)):

    user = await get_users(db, current_user["sub"])

    sql_query = """
       select 
            cp.id, 
            p.code, 
            p.name, 
            p.start_day, 
            p.end_day, 
            p.label, 
            p.discount, 
            p.point 
        from customer_promotions cp 
        inner join promotion p on cp.id_promotion = p.id
        where cp.id_users = :user_id
        and cp.status = 1;
       """

    # Execute the SQL query
    filtered_data = await db.fetch_all(sql_query, values={"user_id": user["id"]})

    result_json = {
        'customer_promotions': [
            {
                "id": item['id'],
                "code": item['code'],
                "name": item['name'],
                "start_day": item['start_day'],
                "end_day": item['end_day'],
                "label": item['label'],
                "discount": item['discount'],
                "point": item['point']
            }
            for item in filtered_data
        ],
        'status':'OK'
    }

    return JSONResponse(content=result_json, media_type="application/json; charset=UTF-8")


# #cập nhật gcoin
# @app.post("/update-g-coin/", response_model=Message)
# async def update_g_coin(update_GCoin: GCoinUpdale,current_user: dict = Depends(verify_jwt_token),  db: Session = Depends(get_database)):
#
#     user = await get_users(db, current_user["sub"])
#
#     db_promotions = GCoinUpdale(**update_GCoin.dict())
#
#
#     update_query = update(Users).where(Users.email == update_forgot_password.email).values(
#         password=update_forgot_password.newPassword)
#
#     await db.execute(update_query)
#     return Message(detail=0)


#----------------Location--------------------
# Thêm Vị trí người dùng
@app.post("/create-location/", response_model=Message)
async def create_location(add_create_location: CreateLocation,current_user: dict = Depends(verify_jwt_token),  db: Session = Depends(get_database)):
    id = "LC-" + random_id()
    user = await get_users(db, current_user["sub"])
    defaultt = 0

    query = select(Location).where(Location.id_users == user['id'])
    otb_old = await db.fetch_one(query)

    if otb_old:
        defaultt = 0
    else:
        defaultt = 1

    db_location = Location(id=id, **add_create_location.dict())

    async with db.transaction():
        pass
    await db.execute(Location.__table__.insert().values(
        id=id,
        id_users=user['id'],
        location=db_location.location,
        location2=db_location.location2,
        lat=db_location.lat,
        lng=db_location.lng,
        defaultt=defaultt

    ))

    return Message(detail=0)

@app.get("/get-location/")
async def get_location(current_user: dict = Depends(verify_jwt_token), db: Session = Depends(get_database)):
    # Lấy thông tin người dùng hiện tại
    user = await get_users(db, current_user["sub"])

    rows = await get_db_location(db, user['id'])

    # Chuyển đổi các dòng thành danh sách từ điển
    locations = [dict(row) for row in rows]

    # Tạo một từ điển chứa dữ liệu trả về
    response_data = {"location": locations, "status": "OK"}

    return JSONResponse(content=response_data, media_type="application/json; charset=UTF-8")


@app.get("/get-location-default/")
async def get_location(current_user: dict = Depends(verify_jwt_token), db: Session = Depends(get_database)):

    user = await get_users(db, current_user["sub"])

    rows = await get_db_location(db, user['id'])

    # Chuyển đổi các dòng thành danh sách từ điển
    locations = [dict(row) for row in rows]

    # Tạo một từ điển chứa dữ liệu trả về
    response_data = {"location": locations, "status": "OK"}

    return JSONResponse(content=response_data, media_type="application/json; charset=UTF-8")

@app.delete("/delete-location/")
async def delete_location(delete_lc: DeleteLoccation, db: Session = Depends(get_database)):

    if delete_lc.defaultt == 1:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="NO",
        )

    await get_delete_location(db, delete_lc.id)

    return {"detail": "OK"}

@app.put("/update-location/")
async def update_location(update_lc: UpdateLoccation, db: Session = Depends(get_database)):
    select_lc = select(Location).where((Location.id_users == update_lc.id_users) & (Location.defaultt == 1))
    request_id = await  db.fetch_one(select_lc)

    update_default_lc = update(Location).where(Location.id == request_id['id']).values(defaultt=0)
    await  db.execute(update_default_lc)

    update_defaultt_lc = update(Location).where(Location.id == update_lc.id).values(defaultt=1)
    await  db.execute(update_defaultt_lc)

    return {"detail": "OK"}

@app.put("/put-invoice-detail")
async def put_invoice_detail(id:str,price: int, premiumService: int, workingDay: str, roomArea: str, workTime :str,db: Session = Depends(get_database)):

    update_default_lc = update(InvoiceDetails).where(InvoiceDetails.id == id).values(
        price=price,
        premium_service=premiumService,
        working_day=workingDay,
        room_area=roomArea,
        work_time=workTime
        )
    await  db.execute(update_default_lc)

    return {"detail": "OK"}

# hiển thị thông tin về màn hình home

@app.get("/select-data-home/")
async def select_data_home(current_user: dict = Depends(verify_jwt_token), db: Session = Depends(get_database)):
    user = await get_users(db, current_user["sub"])

    sql_query = """
    SELECT
        u.id,
        u.name AS nameusers,
        u.money,
        u.g_points,
        l.id AS idL,
        l.location,
        l.location2,
    
        s.id AS idS,
        s.name AS namesv,
        s.icon,
        s.label,
        s.status,
    
        p.id AS idP,
        p.name AS nameP,
        p.code AS codeP,
        p.start_day AS startDP,
        p.end_day AS endDP,
        p.content AS contentP,
        p.label AS labelP,
        p.point AS pointP,
        p.discount AS discountP,
    
        b.id AS idB,
        b.imageUrl AS imageUB,
        b.newsUrl AS newsUB,
        b.title AS titleB,
        b.content AS contentB,
        b.date AS dateB,
    
        sl.id AS idSl,
        sl.imageUrl AS imageSL,
        sl.newsUrl AS newsSL,
        
        cp.id AS idCP,
        cp.id_users AS idUCP,
        cp.id_promotion AS idPCP
    FROM
        users u
    LEFT JOIN
        location l ON u.id = l.id_users AND l.defaultt = 1
    LEFT JOIN
        service s ON 1=1
    LEFT JOIN
        promotion p ON 1=1
    LEFT JOIN
        slides sl ON 1=1
    LEFT JOIN
        blog b ON 1=1
    LEFT JOIN
        customer_promotions cp ON 1=1
    WHERE
        u.id = :id
    AND
        (b.status = 1 OR b.id IS NULL)
    ORDER BY s.label ASC
    """

    # Execute the SQL query
    filtered_data = await db.fetch_all(sql_query, values={"id": user["id"]})

    result_json = {
        'id': filtered_data[0]['id'],
        'name': filtered_data[0]['nameusers'],
        'money': filtered_data[0]['money'],
        'g_points': filtered_data[0]['g_points'],
        'idL': filtered_data[0]['idL'],
        'location': filtered_data[0]['location'],
        'location2': filtered_data[0]['location2'],
        'slides': [],
        'service': [],
        'promotion': [],
        'blog': []

    }

    # Dictionary to store unique items based on their IDs
    unique_items = {}

    # Iterate through the filtered data
    for item in filtered_data:
        item_idS = item['idS']
        item_idP = item['idP']
        item_idB = item['idB']
        item_idSl = item['idSl']
        item_idCP = item['idCP']

        if item_idSl not in unique_items:
            unique_items[item_idSl] = {
                'id': item_idSl,
                'imageUrl': item['imageSL'],
                'newsUrl': item['newsSL']
            }
            result_json['slides'].append(unique_items[item_idSl])

        # Check if the item with the same ID has been added already
        if item_idS not in unique_items:
            unique_items[item_idS] = {
                'id': item_idS,
                'name': item['namesv'],
                'icon': item['icon'],
                'label': item['label'],
                'status': item['status']
            }
            result_json['service'].append(unique_items[item_idS])

        if item_idP not in unique_items:
            unique_items[item_idP] = {
                'id': item_idP,
                'nameP': item['nameP'],
                'codeP': item['codeP'],
                'startDP': item['startDP'],
                'endDP': item['endDP'],
                'contentP': item['contentP'],
                'labelP': item['labelP'],
                'discountP': item['discountP'],
                'pointP': item['pointP']
            }
            result_json['promotion'].append(unique_items[item_idP])

        if item_idB not in unique_items:
            unique_items[item_idB] = {
                'id': item_idB,
                'imageUrl': item['imageUB'],
                'newsUrl': item['newsUB'],
                'title': item['titleB'],
                'content': item['contentB'],
                'date': item['dateB']
            }
            result_json['blog'].append(unique_items[item_idB])

    return JSONResponse(content=result_json, media_type="application/json; charset=UTF-8")

@app.post("/create-invoice/", response_model=Message)
async def create_invoice(add_create_invoice: CreateInvoice, current_user: dict = Depends(verify_jwt_token), db: Session = Depends(get_database)):

    idIV = "IV-" + random_id()
    idIVD = "IVD-" + random_id()
    idN = "N-" + random_id()
    idBF = "BF-" + random_id()
    sv = ""
    gsv = ""

    user = await get_users(db, current_user["sub"])
    db_invoice = CreateInvoice(**add_create_invoice.dict())

    current_datetime = datetime.now()

    async with db.transaction():

        if db_invoice.paymentMethods == 2:
            moneys = user['money'] - db_invoice.price
            await db.execute(update(Users).where(Users.id == user['id']).values(money=moneys))

        if db_invoice.gPoints != 0:

            gPoints = user['g_points'] + db_invoice.gPoints
            await db.execute(update(Users).where(Users.id == user['id']).values(g_points=gPoints))
            await db.execute(update(CustomerPromotions).where(CustomerPromotions.id == db_invoice.idP).values(status=0))

        if db_invoice.label == 1:
            sv = "Lịch dọn dẹp nhà"
            gsv = "Gói dọn dẹp: " + db_invoice.workingDay

        await db.execute(Invoice.__table__.insert().values(
            id=idIV,
            label=db_invoice.label,
            id_users=user['id'],
            repeat=db_invoice.repeat,
            repeat_state=db_invoice.repeat_state,
            duration=db_invoice.duration,
            cancel_repeat=0,
            removal_date=db_invoice.removal_date
        ))

        await db.execute(InvoiceDetails.__table__.insert().values(
            id=idIVD,
            id_invoice=idIV,
            id_partner="",
            name_user=db_invoice.nameUser,
            phone_number=db_invoice.phoneNumber,
            location=db_invoice.location,
            location2=db_invoice.location2,
            lat=db_invoice.lat,
            lng=db_invoice.lng,
            posting_time=current_datetime,
            working_day=db_invoice.workingDay,
            work_time=db_invoice.workTime,
            room_area=db_invoice.roomArea,
            pet_note=db_invoice.petNote,
            employee_note=db_invoice.employeeNote,
            payment_methods=db_invoice.paymentMethods,
            price=db_invoice.price,
            order_status=1,
            cancel_job="",
            reason_cancellation="",
            cancellation_time_completed="",
            cancellation_fee=0,
            premium_service=db_invoice.premium_service,
            number_sessions=db_invoice.number_sessions,

        ))

        await db.execute(Notification.__table__.insert().values(
            id=idN,
            id_invoice_details=idIVD,
            id_users=user['id'],
            title=sv,
            content=gsv,
            posting_time=current_datetime,
            status_notification=1,
        ))

        if db_invoice.paymentMethods == 2 :
            await db.execute(BalanceFluctuations.__table__.insert().values(
                id=idBF,
                id_customer=user['id'],
                money=db_invoice.price,
                note=db_invoice.note,
                date=current_datetime,
                wallet="Ví 3CleanPay",
                status=0
            ))

    return Message(detail=0)


#get chờ làm
@app.get("/get-pending-invoice/", response_model=Message)
async def get_pending_invoice(current_user: dict = Depends(verify_jwt_token), db: Session = Depends(get_database)):

    user = await get_users(db, current_user["sub"])

    sql_query = '''
          SELECT 
    id.id AS idID, 
    i.id AS idIV, 
    p.id AS idP,
    id.id_partner AS idPT,
    u.name AS nameU,
    u.phoneNumber,
    i.label,
    i.duration,
    id.number_sessions,
    pt.image AS imagePT,
    pt.name AS namePT,
    pt.one_star AS oneStarPT,
    pt.two_star AS twoStarPT,
    pt.three_star AS threeStarPT,
    pt.four_star AS fourStarPT,
    pt.five_star AS fiveStarPT,
    p.one_star AS oneStarP,
    p.two_star AS twoStarP,
    p.three_star AS threeStarP,
    p.four_star AS fourStarP,
    p.five_star AS fiveStarP,
    id.posting_time,
    id.working_day, 
    id.work_time, 
    id.room_area,
    i.repeat, 
    id.location, 
    id.price, 
    id.payment_methods,
    id.premium_service,
    id.pet_note, 
    id.employee_note, 
    i.repeat_state,
    id.order_status,
    p.image AS imageP,
    p.name AS nameP,
    pt.phonenumber AS phonenumberPT
FROM users u 
INNER JOIN invoice i ON u.id = i.id_users
INNER JOIN invoice_details id ON i.id = id.id_invoice
LEFT JOIN accept_job aj ON id.id = aj.id_invoice_details AND aj.status = 1
LEFT JOIN partner p ON aj.id_partner = p.id
LEFT JOIN partner pt ON pt.id = id.id_partner
WHERE u.id = :user_id
and id.order_status IN (1,2,3, 4)
AND (aj.id IS NULL OR id.id_partner IS NULL OR pt.id IS NULL)
ORDER BY 
    strftime('%Y-%m-%d %H:%M:%S', posting_time) DESC;
       '''

    # Execute the SQL query
    filtered_data = await db.fetch_all(sql_query, values={"user_id": user["id"]})

    result_dict = {}

    for item in filtered_data:
        if item['idID'] not in result_dict:
            partner_info = []
            if item['idPT'] is not None:
                partner_info.append({
                    "idP": item['idP'],
                    "imageP": item['imageP'],
                    "nameP": item['nameP'],
                    "oneStar": item['oneStarP'],
                    "twoStar": item['twoStarP'],
                    "threeStar": item['threeStarP'],
                    "fourStar": item['fourStarP'],
                    "fiveStar": item['fiveStarP']
                })

            result_dict[item['idID']] = {
                "idID": item['idID'],
                "idIV": item['idIV'],
                "idPT": item['idPT'],
                "phonenumberPT": item['phonenumberPT'],
                "label": item['label'],
                "duration": item['duration'],
                "number_sessions": item['number_sessions'],
                "imagePT": item['imagePT'],
                "namePT": item['namePT'],
                "phoneNumber": item['phoneNumber'],
                "nameU": item['nameU'],
                "postingTime": item['posting_time'],
                "workingDay": item['working_day'],
                "workTime": item['work_time'],
                "repeat": item['repeat'],
                "location": item['location'],
                "price": item['price'],
                "roomArea": item['room_area'],
                "petNotes": item['pet_note'],
                "employeeNotes": item['employee_note'],
                "premiumService": item['premium_service'],
                "orderStatus": item['order_status'],
                "repeatState": item['repeat_state'],
                "payment_methods": item['payment_methods'],
                "oneStar": item['oneStarPT'],
                "twoStar": item['twoStarPT'],
                "threeStar": item['threeStarPT'],
                "fourStar": item['fourStarPT'],
                "fiveStar": item['fiveStarPT'],
                "partner": partner_info
            }
        else:
            # Nếu idIV đã tồn tại trong từ điển, chỉ cập nhật thông tin partner (nếu có)
            if item['idPT'] is not None:
                partner_info = {
                    "idP": item['idP'],
                    "imageP": item['imageP'],
                    "nameP": item['nameP'],
                    "oneStar": item['oneStarP'],
                    "twoStar": item['twoStarP'],
                    "threeStar": item['threeStarP'],
                    "fourStar": item['fourStarP'],
                    "fiveStar": item['fiveStarP']
                }
                result_dict[item['idID']]['partner'].append(partner_info)

    # Chuyển đổi từ điển thành danh sách để trả về
    result_json = list(result_dict.values())

    return JSONResponse(content={"pending_invoices": result_json, "status": "OK"},
                        media_type="application/json; charset=UTF-8")

@app.get("/get-periodically/", response_model=Message)
async def get_periodically(current_user: dict = Depends(verify_jwt_token), db: Session = Depends(get_database)):

    user = await get_users(db, current_user["sub"])

    sql_query = '''
          SELECT 
    id.id AS idID, 
    i.id AS idIV, 
    p.id AS idP,
    id.id_partner AS idPT,
    u.name AS nameU,
    u.phoneNumber,
    i.label,
    i.duration,
    id.number_sessions,
    pt.image AS imagePT,
    pt.name AS namePT,
    pt.one_star AS oneStarPT,
    pt.two_star AS twoStarPT,
    pt.three_star AS threeStarPT,
    pt.four_star AS fourStarPT,
    pt.five_star AS fiveStarPT,
    p.one_star AS oneStarP,
    p.two_star AS twoStarP,
    p.three_star AS threeStarP,
    p.four_star AS fourStarP,
    p.five_star AS fiveStarP,
    i.cancel_repeat,
    id.posting_time,
    id.working_day, 
    id.work_time, 
    id.room_area,
    i.repeat, 
    id.location, 
    id.price, 
    id.payment_methods,
    id.premium_service,
    id.pet_note, 
    id.employee_note, 
    i.repeat_state,
    id.order_status,
    p.image AS imageP,
    p.name AS nameP,
    pt.phonenumber AS phonenumberPT
FROM users u 
INNER JOIN invoice i ON u.id = i.id_users
INNER JOIN invoice_details id ON i.id = id.id_invoice
LEFT JOIN accept_job aj ON id.id = aj.id_invoice_details AND aj.status = 1
LEFT JOIN partner p ON aj.id_partner = p.id
LEFT JOIN partner pt ON pt.id = id.id_partner
WHERE u.id = :user_id
  AND id.order_status IN (0, 1, 2, 3, 4)
  AND i.cancel_repeat = 0
  AND i.duration != ""
  AND (aj.id IS NULL OR id.id_partner IS NULL OR pt.id IS NULL)
ORDER BY 
    strftime('%Y-%m-%d %H:%M:%S', posting_time) DESC;
       '''

    # Execute the SQL query
    filtered_data = await db.fetch_all(sql_query, values={"user_id": user["id"]})

    result_dict = {}

    for item in filtered_data:
        if item['idID'] not in result_dict:
            partner_info = []
            if item['idPT'] is not None:
                partner_info.append({
                    "idP": item['idP'],
                    "imageP": item['imageP'],
                    "nameP": item['nameP'],
                    "oneStar": item['oneStarP'],
                    "twoStar": item['twoStarP'],
                    "threeStar": item['threeStarP'],
                    "fourStar": item['fourStarP'],
                    "fiveStar": item['fiveStarP']
                })

            result_dict[item['idID']] = {
                "idID": item['idID'],
                "idIV": item['idIV'],
                "idPT": item['idPT'],
                "phonenumberPT": item['phonenumberPT'],
                "label": item['label'],
                "duration": item['duration'],
                "number_sessions": item['number_sessions'],
                "cancelRepeat": item['cancel_repeat'],
                "imagePT": item['imagePT'],
                "namePT": item['namePT'],
                "phoneNumber": item['phoneNumber'],
                "nameU": item['nameU'],
                "postingTime": item['posting_time'],
                "workingDay": item['working_day'],
                "workTime": item['work_time'],
                "repeat": item['repeat'],
                "location": item['location'],
                "price": item['price'],
                "roomArea": item['room_area'],
                "petNotes": item['pet_note'],
                "employeeNotes": item['employee_note'],
                "premiumService": item['premium_service'],
                "orderStatus": item['order_status'],
                "repeatState": item['repeat_state'],
                "payment_methods": item['payment_methods'],
                "oneStar": item['oneStarPT'],
                "twoStar": item['twoStarPT'],
                "threeStar": item['threeStarPT'],
                "fourStar": item['fourStarPT'],
                "fiveStar": item['fiveStarPT'],
                "partner": partner_info
            }
        else:
            # Nếu idIV đã tồn tại trong từ điển, chỉ cập nhật thông tin partner (nếu có)
            if item['idPT'] is not None:
                partner_info = {
                    "idP": item['idP'],
                    "imageP": item['imageP'],
                    "nameP": item['nameP'],
                    "oneStar": item['oneStarP'],
                    "twoStar": item['twoStarP'],
                    "threeStar": item['threeStarP'],
                    "fourStar": item['fourStarP'],
                    "fiveStar": item['fiveStarP']
                }
                result_dict[item['idID']]['partner'].append(partner_info)

    # Chuyển đổi từ điển thành danh sách để trả về
    result_json = list(result_dict.values())

    return JSONResponse(content={"periodic": result_json, "status": "OK"},
                        media_type="application/json; charset=UTF-8")
@app.get("/get-history/", response_model=Message)
async def get_history(current_user: dict = Depends(verify_jwt_token), db: Session = Depends(get_database)):

    user = await get_users(db, current_user["sub"])

    sql_query = '''
          SELECT 
    id.id AS idID, 
    i.id AS idIV, 
    p.id AS idP,
    id.id_partner AS idPT,
    u.name AS nameU,
    u.phoneNumber,
    i.label,
    i.duration,
    pt.image AS imagePT,
    pt.name AS namePT,
    pt.one_star AS oneStarPT,
    pt.two_star AS twoStarPT,
    pt.three_star AS threeStarPT,
    pt.four_star AS fourStarPT,
    pt.five_star AS fiveStarPT,
    p.one_star AS oneStarP,
    p.two_star AS twoStarP,
    p.three_star AS threeStarP,
    p.four_star AS fourStarP,
    p.five_star AS fiveStarP,
    id.posting_time,
    id.working_day, 
    id.work_time, 
    id.room_area,
    i.repeat, 
    id.location, 
    id.price, 
    id.payment_methods,
    id.premium_service,
    id.pet_note, 
    id.employee_note, 
    id.cancel_job,
    i.repeat_state,
    id.order_status,
    id.reason_cancellation,
    id.cancellation_time_completed,
    id.number_sessions,
    id.cancellation_fee,
    p.image AS imageP,
    p.name AS nameP,
    pt.phonenumber AS phonenumberPT
FROM users u 
INNER JOIN invoice i ON u.id = i.id_users
INNER JOIN invoice_details id ON i.id = id.id_invoice
LEFT JOIN accept_job aj ON id.id = aj.id_invoice_details AND aj.status = 1
LEFT JOIN partner p ON aj.id_partner = p.id
LEFT JOIN partner pt ON pt.id = id.id_partner
WHERE u.id = :user_id
and id.order_status IN (0,5,6)
AND (aj.id IS NULL OR id.id_partner IS NULL OR pt.id IS NULL)
ORDER BY 
    strftime('%Y-%m-%d %H:%M:%S', posting_time) DESC;

       '''

    # Execute the SQL query
    filtered_data = await db.fetch_all(sql_query, values={"user_id": user["id"]})

    result_dict = {}

    for item in filtered_data:
        if item['idID'] not in result_dict:
            partner_info = []
            if item['idPT'] is not None:
                partner_info.append({
                    "idP": item['idP'],
                    "imageP": item['imageP'],
                    "nameP": item['nameP'],
                    "oneStar": item['oneStarP'],
                    "twoStar": item['twoStarP'],
                    "threeStar": item['threeStarP'],
                    "fourStar": item['fourStarP'],
                    "fiveStar": item['fiveStarP']
                })

            result_dict[item['idID']] = {
                "idID": item['idID'],
                "idIV": item['idIV'],
                "idPT": item['idPT'],
                "duration": item['duration'],
                "phonenumberPT": item['phonenumberPT'],
                "label": item['label'],
                "imagePT": item['imagePT'],
                "namePT": item['namePT'],
                "phoneNumber": item['phoneNumber'],
                "cancellationFee": item['cancellation_fee'],
                "number_sessions": item['number_sessions'],
                "nameU": item['nameU'],
                "postingTime": item['posting_time'],
                "workingDay": item['working_day'],
                "workTime": item['work_time'],
                "repeat": item['repeat'],
                "location": item['location'],
                "price": item['price'],
                "roomArea": item['room_area'],
                "petNotes": item['pet_note'],
                "employeeNotes": item['employee_note'],
                "premiumService": item['premium_service'],
                "orderStatus": item['order_status'],
                "repeatState": item['repeat_state'],
                "payment_methods": item['payment_methods'],
                "oneStar": item['oneStarPT'],
                "twoStar": item['twoStarPT'],
                "threeStar": item['threeStarPT'],
                "fourStar": item['fourStarPT'],
                "cancelJob": item['cancel_job'],
                "reasonCancellation": item['reason_cancellation'],
                "cancellationTimeCompleted": item['cancellation_time_completed'],
                "fiveStar": item['fiveStarPT'],
                "partner": partner_info
            }
        else:
            # Nếu idIV đã tồn tại trong từ điển, chỉ cập nhật thông tin partner (nếu có)
            if item['idPT'] is not None:
                partner_info = {
                    "idP": item['idP'],
                    "imageP": item['imageP'],
                    "nameP": item['nameP'],
                    "oneStar": item['oneStarP'],
                    "twoStar": item['twoStarP'],
                    "threeStar": item['threeStarP'],
                    "fourStar": item['fourStarP'],
                    "fiveStar": item['fiveStarP']
                }
                result_dict[item['idID']]['partner'].append(partner_info)

    # Chuyển đổi từ điển thành danh sách để trả về
    result_json = list(result_dict.values())

    return JSONResponse(content={"pending_invoices": result_json, "status": "OK"},
                        media_type="application/json; charset=UTF-8")


#get thông báo lịch làm việc
@app.get("/get-calendar/")
async def get_calendar(current_user: dict = Depends(verify_jwt_token), db: Session = Depends(get_database)):
    user = await get_users(db, current_user["sub"])

    query = Notification.__table__.select().order_by(desc(Notification.posting_time)).where(Notification.id_users==user['id'])
    db_notification_calendar = await db.fetch_all(query)

    notification_calendar = [dict(row) for row in db_notification_calendar]

    # Tạo một từ điển chứa dữ liệu trả về
    response_data = {"notification_calendar": notification_calendar, "status": "OK"}

    return JSONResponse(content=response_data, media_type="application/json; charset=UTF-8")

@app.get("/get-work-completed")
async def get_work_completed(id: str, db: Database = Depends(get_database)):
    sql_query = '''
                SELECT 
                    i.id AS invoice_id, 
                    (
                        SELECT COUNT(*) 
                        FROM invoice_details id 
                        WHERE id.id_invoice = :id AND id.order_status IN (5, 6)
                    ) AS invoice_details_count
                FROM 
                    invoice i
                WHERE 
                    i.id = :id;
               '''

    # Execute the SQL query
    result = await db.fetch_one(query=sql_query, values={"id": id})

    # Get the count directly from the result
    invoice_details_count = result["invoice_details_count"]

    # Create a dictionary to return the response data
    response_data = {"work-completed": invoice_details_count, "status": "OK"}

    return JSONResponse(content=response_data, media_type="application/json; charset=UTF-8")

@app.post("/post-periodically-canneled/", response_model=Message)
async def post_periodically_canneled(stt: int, idI: str, money: int, current_user: dict = Depends(verify_jwt_token), db: Session = Depends(get_database)):

    print(idI)
    user = await get_users(db, current_user["sub"])
    idBF = "BF" + random_id()
    current_datetime = datetime.now()
    if stt == 0:
        moneys = user['money'] + money

        async with db.transaction():
            await db.execute(update(Users).where(Users.id == user['id']).values(money=moneys))
            await db.execute(update(Invoice).where(Invoice.id == idI).values(cancel_repeat=1))
            await db.execute(BalanceFluctuations.__table__.insert().values(
                id=idBF,
                id_customer=user['id'],
                money=money,
                note="Hoàn tiền dịch vụ",
                date=current_datetime,
                wallet="Từ hệ thống",
                status=3
            ))
        return Message(detail=0)
    else:
        print("Chưa hoàn thành")

    return Message(detail=0)
@app.get("/partner/get-user/")
async def get_user(current_user: dict = Depends(verify_jwt_token), db: Session = Depends(get_database)):
    # Lấy thông tin người dùng hiện tại
    user = await get_partner(db, current_user["sub"])

    rows = await get_db_partner(db, user['id'])

    # Chuyển đổi các dòng thành danh sách từ điển

    user = [dict(row) for row in rows]

    # Tạo một từ điển chứa dữ liệu trả về
    response_data = {"user": user, "status": "OK"}

    return JSONResponse(content=response_data, media_type="application/json; charset=UTF-8")
    
@app.get("/partner/statistics/")
async def get_statistics(id_partner: str, start_date: str, end_date: str, current_user: dict = Depends(verify_jwt_token), db: Session = Depends(get_database)):
    # Convert string input to datetime objects
    try:
        start_datetime = datetime.strptime(start_date, '%Y-%m-%d %H:%M:%S')
        end_datetime = datetime.strptime(end_date, '%Y-%m-%d %H:%M:%S')
    except ValueError:
        raise HTTPException(status_code=400, detail="Invalid date format. Use YYYY-MM-DD HH:MM:SS.")

    sql_query = '''
                SELECT 
                    COUNT(*) AS vcdl,
                    SUM(id.price) AS price,
                    COUNT(CASE WHEN e.star > 2 THEN 1 ELSE NULL END) AS blt,
                    COUNT(CASE WHEN e.star < 2 THEN 1 ELSE NULL END) AS blx
                FROM 
                    Partner p
                INNER JOIN 
                    Invoice_details id ON p.id = id.id_partner
                INNER JOIN 
                    evaluate e ON e.id_partner = p.id
                WHERE 
                    id.id_partner = :id_partner
                    AND id.order_status = 6
                    AND id.cancellation_time_completed BETWEEN :start_date AND :end_date
                    AND e.date BETWEEN :start_date AND :end_date;
               '''

    # Execute the SQL query
    result = await db.execute(text(sql_query), {
        "id_partner": id_partner,
        "start_date": start_datetime,
        "end_date": end_datetime
    })
    row = result.fetchone()

    if row is None:
        raise HTTPException(status_code=404, detail="No records found.")

    # Create a dictionary to return the response data
    response_data = {
        "vcdl": row.vcdl,
        "price": row.price,
        "blt": row.blt,
        "blx": row.blx,
        "status": "OK"
    }

    return JSONResponse(content=response_data, media_type="application/json; charset=UTF-8")
#get thông tin công viêệc chi tiết
@app.get("/get-job-details/")
async def get_job_details(id: str, db: Session = Depends(get_database)):
    sql_query = '''
            SELECT 
            id.id AS idIVD, 
            i.id AS idIV, 
            p.id AS idP,
            id.id_partner AS idPT,
            u.id AS idU,
            u.name AS nameU,
            u.image AS imageU,
            u.phoneNumber,
            i.label,
            pt.image AS imagePT,
            pt.name AS namePT,
            pt.one_star AS oneStarPT,
            pt.two_star AS twoStarPT,
            pt.three_star AS threeStarPT,
            pt.four_star AS fourStarPT,
            pt.five_star AS fiveStarPT,
            p.one_star AS oneStarP,
            p.two_star AS twoStarP,
            p.three_star AS threeStarP,
            p.four_star AS fourStarP,
            p.five_star AS fiveStarP,
            id.posting_time,
            id.working_day, 
            id.work_time, 
            id.room_area,
            i.repeat, 
            i.location, 
            id.price, 
            id.payment_methods,
            i.pet_notes, 
            i.employee_notes, 
            i.invoice_status,
            i.repeat_state,
            id.order_status,
            p.image AS imageP,
            p.name AS nameP
        FROM users u INNER JOIN invoice i
        ON u.id = i.id_users
        INNER JOIN invoice_details id ON i.id = id.id_invoice
        LEFT JOIN accept_job aj ON id.id_invoice = aj.id_invoice_details
        LEFT JOIN partner p ON aj.id_partner = p.id
        LEFT JOIN partner pt ON pt.id = id.id_partner
        WHERE aj.id IS NULL
        AND (id.id_partner IS NULL OR pt.id IS NULL)
        AND id.id = :id
        ORDER BY 
        strftime('%Y-%m-%d %H:%M:%S', posting_time) DESC;
           '''

    # Execute the SQL query
    filtered_data = await db.fetch_all(sql_query, values={"id": id})

    result_json = []

    for item in filtered_data:
        partner_info = []
        if item['idPT'] is not None:
            partner_info.append({
                "idP": item['idP'],
                "imageP": item['imageP'],
                "nameP": item['nameP'],
                "oneStar":item['oneStarP'],
                "twoStar":item['twoStarP'],
                "threeStar":item['threeStarP'],
                "fourStar":item['fourStarP'],
                "fiveStar":item['fiveStarP']
            })

        # Check each field to ensure the value is not null before adding to result_json
        result_item = {
            "idIV": item['idIV'],
            "idPT": item['idPT'],
            "idU": item['idU'],
            "label": item['label'],
            "imagePT": item['imagePT'],
            "namePT": item['namePT'],
            "imageU":item['imageU'],
            "phoneNumber": item['phoneNumber'],
            "nameU": item['nameU'],
            "postingTime": item['posting_time'],
            "workingDay": item['working_day'],
            "workTime": item['work_time'],
            "repeat": item['repeat'],
            "location": item['location'],
            "price": item['price'],
            "roomArea": item['room_area'],
            "petNotes": item['pet_notes'],
            "employeeNotes": item['employee_notes'],
            "orderStatus": item['order_status'],
            "invoiceStatus": item['invoice_status'],
            "repeatState": item['repeat_state'],
            "payment_methods": item['payment_methods'],
            "oneStar": item['oneStarPT'],
            "twoStar": item['twoStarPT'],
            "threeStar": item['threeStarPT'],
            "fourStar": item['fourStarPT'],
            "fiveStar": item['fiveStarPT'],
            "partner": partner_info
        }

        result_json.append(result_item)

    return (JSONResponse(content={"job_details": result_json, "status": "OK"},
                          media_type="application/json; charset=UTF-8"))

@app.put("/put-notification/")
async def update_users_admin( id: str, db: Session = Depends(get_database)):
    update_query = update(Notification).where(Notification.id == id).values(
        status_notification=0,
    )
    await db.execute(update_query)

    return Message(detail=0)

#get thông báo lịch làm việc
@app.get("/get-service/")
async def get_service(db: Session = Depends(get_database)):

    query = Service.__table__.select().where(Service.status==1)
    db_service = await db.fetch_all(query)

    service = [dict(row) for row in db_service]

    # Tạo một từ điển chứa dữ liệu trả về
    response_data = {"service": service, "status": "OK"}

    return JSONResponse(content=response_data, media_type="application/json; charset=UTF-8")


@app.get("/get-3clean-wallet/")
async def get_3clean_wallet(current_user: dict = Depends(verify_jwt_token), db: Session = Depends(get_database)):

    user = await get_users(db, current_user["sub"])
    sql_query = f'''
  select 
bf.id, 
u.money AS moneyU, 
bf.money AS moneyBF, 
bf.note, 
bf.date, 
bf.wallet,
bf.status 
from users u 
left join balance_fluctuations bf on u.id = bf.id_customer
where 
u.id = :id
ORDER BY 
        strftime('%Y-%m-%d %H:%M:%S', bf.date) DESC;
               '''

    # Execute the SQL query
    filtered_data = await db.fetch_all(sql_query,  values={"id": user["id"]})

    result_json = {}
    wallet=[]
    if filtered_data:
        item = filtered_data[0]
        result_json = {
            "moneyU": item['moneyU'],
            'wallet':wallet,

        }
        for item in filtered_data:
            if item['id'] is not None:
                wallet.append({
                    "id": item['id'],
                    "moneyBF": item['moneyBF'],
                    "note": item['note'],
                    "date": item['date'],
                    "wallet": item['wallet'],
                    "status": item['status'],
                })

    return (JSONResponse(content={"3clean_wallet": result_json, "status": "OK"},
                         media_type="application/json; charset=UTF-8"))



@app.post("/post-recharge/", response_model=Message)
async def post_recharge(add_create_partner: CreateWallet, current_user: dict = Depends(verify_jwt_token),  db: Session = Depends(get_database)):
    idBF = "BF-" + random_id()
    user = await get_users(db, current_user["sub"])
    db_create_wallet = CreateWallet(**add_create_partner.dict())
    current_datetime = datetime.now()

    async with db.transaction():
        await db.execute(update(Users).where(Users.id == user['id']).values(money=db_create_wallet.money))
        await db.execute(BalanceFluctuations.__table__.insert().values(
            id=idBF,
            id_customer=user['id'],
            money=db_create_wallet.price,
            note=db_create_wallet.note,
            date=current_datetime,
            wallet=db_create_wallet.wallet,
            status=db_create_wallet.status
        ))

    return Message(detail=0)



@app.put("/put-accept-job/")
async def put_accept_job(idParther: str, idInvoiceDetails: str, db: Session = Depends(get_database)):
    update_query = update(InvoiceDetails).where(InvoiceDetails.id == idInvoiceDetails).values(id_partner=idParther, order_status=3)
    await db.execute(update_query)
    delete_query = AcceptJob.__table__.delete().where(AcceptJob.id_invoice_details == idInvoiceDetails)
    await db.execute(delete_query)
    return {"detail": "OK"}


@app.get("/get-partner-information/")
async def get_partner_information(id: str, db: Session = Depends(get_database)):
    sql_query = f'''
      select 
        p.id AS idP,
        e.id AS idE,
        p.name AS nameP, 
        u.name AS nameU,
        p.image AS imageP,
        u.image AS imageU,
        p.one_star AS oneStarP,
        p.two_star AS twoStarP,
        p.three_star AS threeStarP,
        p.four_star AS fourStarP,
        p.five_star AS fiveStarP,
        e.content,
        e.star,
        e.date,
        e.image
     from partner p 
     left join evaluate e on p.id= e.id_partner 
     left join users u on e.id_user = u.id
    where p.id =:id
        '''

    # Execute the SQL query
    filtered_data = await db.fetch_all(sql_query, values={"id": id})

    partner_info = {
        "idP": filtered_data[0]['idP'],
        "nameP": filtered_data[0]['nameP'],
        "imageP": filtered_data[0]['imageP'],
        "oneStar": filtered_data[0]['oneStarP'],
        "twoStar": filtered_data[0]['twoStarP'],
        "threeStar": filtered_data[0]['threeStarP'],
        "fourStar": filtered_data[0]['fourStarP'],
        "fiveStar": filtered_data[0]['fiveStarP'],
        "user": []
    }

    # Populate the user reviews
    for item in filtered_data:
        if item['idE'] is not None:
            user_review = {
                "idE": item['idE'],
                "nameU": item['nameU'],
                "imageU": item['imageU'],
                "star": item['star'],
                "content": item['content'],
                "date": item['date'],
                "image": item['image']
            }
            partner_info["user"].append(user_review)

    return (JSONResponse(content={"partner_information": partner_info, "status": "OK"},
                         media_type="application/json; charset=UTF-8"))

@app.put("/put-cancel-job/")
async def put_cancel_job(idU: str,reason_cancellation: str, stt: int, price: int, idInvoiceDetails: str, current_user: dict = Depends(verify_jwt_token), db: Session = Depends(get_database)):
    current_datetime = datetime.now()
    idBF = "idBF-" + random_id()

    if stt == 0:
        user = await get_users(db, current_user["sub"])
        moneys = price + int(user['money'])
        print(f"Updated money for user: {moneys}")

        update_invoice_query = update(InvoiceDetails).where(InvoiceDetails.id == idInvoiceDetails).values(
            order_status=0,
            cancel_job=user['id'],
            reason_cancellation=reason_cancellation,
            cancellation_time_completed=current_datetime,
            cancellation_fee=price
        )

        update_user_query = update(Users).where(Users.id == idU).values(money=moneys)

        await db.execute(update_invoice_query)
        await db.execute(update_user_query)
        await db.execute(BalanceFluctuations.__table__.insert().values(
            id=idBF,
            id_customer=user['id'],
            money=price,
            note="Hoàn tiền dịch vụ",
            date=current_datetime,
            wallet="Từ hệ thống",
            status=3
        ))
    else:
        user = await get_partner(db, current_user["sub"])
        users = await get_db_user(db, idU)
        moneys = price + int(users['money'])
        print(f"Updated money for partner: {moneys}")

        update_invoice_query = update(InvoiceDetails).where(InvoiceDetails.id == idInvoiceDetails).values(
            order_status=0,
            cancel_job=user['id'],
            reason_cancellation=reason_cancellation,
            cancellation_time_completed=current_datetime,
            cancellation_fee=price
        )

        await db.execute(update_invoice_query)
        await db.execute(BalanceFluctuations.__table__.insert().values(
            id=idBF,
            id_customer=users['id'],
            money=price,
            note="Hoàn tiền dịch vụ",
            date=current_datetime,
            wallet="Từ hệ thống",
            status=3
        ))
    return {"detail": "OK"}
@app.put("/put-complete/")
async def put_completee(add_create_partner: CreateWalletU,  db: Session = Depends(get_database)):
    current_datetime = datetime.now()
    idBF = "BF-" + random_id()
    db_create_wallet = CreateWalletU(**add_create_partner.dict())

    user = await get_partner_id(db, db_create_wallet.idP)

    p = db_create_wallet.money + int(user['money'])
    current_datetime = datetime.now()
    async with db.transaction():
        await db.execute(update(InvoiceDetails).where(InvoiceDetails.id == db_create_wallet.id).values(order_status=5, cancellation_time_completed=current_datetime))

        await db.execute(update(Partner).where(Partner.id == db_create_wallet.idP).values(money=p))

        await db.execute(BalanceFluctuations.__table__.insert().values(
            id=idBF,
            id_customer=user['id'],
            money=db_create_wallet.money,
            note=db_create_wallet.note,
            date=current_datetime,
            wallet=db_create_wallet.wallet,
            status=db_create_wallet.status
        ))
    return {"detail": "OK"}



#------------------Doi tac -----------------------

#Tao tai khoan doi tac
@app.post("/partner/create-partner/", response_model=Message)
async def create_partner(add_create_partner: CreatePartner,db: Session = Depends(get_database)):

    idP = "P-" + random_id()
    
    db_partner = CreatePartner(**add_create_partner.dict())

    async with db.transaction():
        await db.execute(Partner.__table__.insert().values(
            id=idP,
            id_admin="",
            email=db_partner.email,
            phonenumber=db_partner.phonenumber,
            password=db_partner.password,
            name=db_partner.name,
            one_star=0,
            two_star=0,
            three_star=0,
            four_star=0,
            five_star=0,
            service=db_partner.service,
            image=db_partner.image,
            datebirth=db_partner.datebirth,
            cccd=db_partner.cccd,
            date_cccd=db_partner.date_cccd,
            address=db_partner.address,
            sex=db_partner.sex,
            date="",
            money=0,
            ban=0,
            censorship=0,
        ))

    return Message(detail=0)


# Đăng nhập người dùng
@app.post("/partner/login-partner/")
async def login_partner(form_data: dict, db: Session = Depends(get_database)):

    email = form_data["email"]
    password = form_data["password"]

    # Lấy thông tin người dùng từ cơ sở dữ liệu
    user = await get_partner(db, email)

    # Kiểm tra thông tin đăng nhập
    if user is None or user["email"] != email:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail=-1,
            headers={"WWW-Authenticate": "Bearer"},
        )

    # kiểm tra mật khẩu
    if user is None or user["password"] != password:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail=-2,
            headers={"WWW-Authenticate": "Bearer"},
        )

    if user is None or user["ban"] != 0:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail=-3,
            headers={"WWW-Authenticate": "Bearer"},
        )
    if user is None or user["censorship"] == 0:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail=-4,
            headers={"WWW-Authenticate": "Bearer"},
        )

    # Tạo JWT token
    token_data = {"sub": user["email"], "id": user["id"]}
    token = create_jwt_token(token_data)

    # Trả về token
    return {"access_token": token, "token_type": "bearer"}

#get thông tin tất cả người dùng
@app.get("/partner/get-partner/")
async def get_service(db: Session = Depends(get_database)):

    query = Partner.__table__.select()
    db_service = await db.fetch_all(query)

    service = [dict(row) for row in db_service]

    # Tạo một từ điển chứa dữ liệu trả về
    response_data = {"service": service, "status": "OK"}

    return JSONResponse(content=response_data, media_type="application/json; charset=UTF-8")

@app.get("/partner/get-job/")
async def get_job(current_user: dict = Depends(verify_jwt_token), db: Session = Depends(get_database)):

    user = await get_partner(db, current_user["sub"])
    result = extract_indexes(user['service'])
    print(', '.join(map(str, result)))
    sql_query = f'''
      SELECT 
            id.id,
            id.lat,
            id.lng,
            id.location,
            id.location2,
            i.label,
            i.repeat,
            i.duration,
            id.number_sessions,
            i.repeat_state,
            id.work_time,
            id.pet_note,
            id.employee_note,
            id.room_area,
            id.premium_service,
            id.payment_methods,
            id.order_status,
            id.working_day,
            id.price,
            COALESCE(aj.accept_job_count, 0) AS accept_job_count
        FROM invoice_details id 
        LEFT JOIN invoice i ON id.id_invoice = i.id
        LEFT JOIN (
            SELECT id_invoice_details, COUNT(*) AS accept_job_count
            FROM accept_job
            WHERE id_partner IS NOT NULL
            GROUP BY id_invoice_details
        ) aj ON id.id = aj.id_invoice_details
        WHERE id.cancel_job = ""
        AND id.order_status IN (1, 2)
        and id.id IN (
            SELECT id.id 
            FROM invoice_details id
            WHERE i.label IN ({', '.join(map(str, result))})
        )
        AND id.id NOT IN (
            SELECT id_invoice_details
            FROM accept_job
            WHERE id_partner = :id
        )
        AND NOT EXISTS (
        SELECT 1
        FROM loai_bo_cv
        WHERE loai_bo_cv.id_invoice_details = id.id
        AND loai_bo_cv.id_partner = :id
    )
        ORDER BY 
        strftime('%Y-%m-%d %H:%M:%S', posting_time) DESC;
        '''

    # Execute the SQL query
    filtered_data = await db.fetch_all(sql_query ,values={"id": user['id']})

    result_json = []

    for item in filtered_data:

        # Check each field to ensure the value is not null before adding to result_json
        result_item = {
            "id": item['id'],
            "lat": item['lat'],
            "lng": item['lng'],
            "location": item['location'],
            "repeatState": item['repeat_state'],
            "numberSessions": item['number_sessions'],
            "duration": item['duration'],
            "repeat": item['repeat'],
            "location2": item['location2'],
            "work_time": item['work_time'],
            "pet_notes": item['pet_note'],
            "label": item['label'],
            "employee_notes": item['employee_note'],
            "room_area": item['room_area'],
            "premium_service": item['premium_service'],
            "paymentMethods": item['payment_methods'],
            "order_status": item['order_status'],
            "workingDay": item['working_day'],
            "price": item['price'],
            "accept_job_count": item['accept_job_count']
        }

        result_json.append(result_item)

    return (JSONResponse(content={"job_all": result_json, "status": "OK"},
                         media_type="application/json; charset=UTF-8"))


# Nhận việc
@app.post("/partner/accept-job/", response_model=Message)
async def accept_job(id:str,current_user: dict = Depends(verify_jwt_token), db: Session = Depends(get_database)):
    user = await get_partner(db, current_user["sub"])
    idAJ = "AJ-" + random_id()
    async with db.transaction():
        await db.execute(AcceptJob.__table__.insert().values(
            id=idAJ,
            id_invoice_details=id,
            id_partner=user['id'],
            status=1
        ))
        update_query = update(InvoiceDetails).where(InvoiceDetails.id == id).values(order_status=2)
        await db.execute(update_query)

    return Message(detail=0)


@app.get("/partner/get-wait-confirmation/")
async def get_wait_confirmation(current_user: dict = Depends(verify_jwt_token), db: Session = Depends(get_database)):
    user = await get_partner(db, current_user["sub"])
    sql_query = f'''
      SELECT 
        id.id,
        aj.id AS idAJ,
        id.lat,
        id.lng,
        id.location,
        id.location2,
        i.label,
        i.repeat,
        i.duration,
        id.number_sessions,
        i.repeat_state,
        id.work_time,
        id.pet_note,
        id.employee_note,
        id.room_area,
        id.premium_service,
        id.payment_methods,
        id.order_status,
        id.working_day,
        id.price,
        COALESCE(aj.accept_job_count, 0) AS accept_job_count
    FROM invoice_details id 
    LEFT JOIN invoice i ON id.id_invoice = i.id
    LEFT JOIN (
        SELECT id, id_invoice_details, COUNT(*) AS accept_job_count
        FROM accept_job
        WHERE id_partner IS NOT NULL
        GROUP BY id_invoice_details
    ) aj ON id.id = aj.id_invoice_details
    WHERE id.order_status = 2
    AND id.id IN (
        SELECT id_invoice_details
        FROM accept_job
        WHERE id_partner = :id
        and status = 1
    );
        '''

    # Execute the SQL query
    filtered_data = await db.fetch_all(sql_query, values={"id": user['id']})

    result_json = []

    for item in filtered_data:
        # Check each field to ensure the value is not null before adding to result_json
        result_item = {
            "id": item['id'],
            "idAJ": item['idAJ'],
            "lat": item['lat'],
            "lng": item['lng'],
            "location": item['location'],
            "repeatState": item['repeat_state'],
            "numberSessions": item['number_sessions'],
            "duration": item['duration'],
            "repeat": item['repeat'],
            "location2": item['location2'],
            "work_time": item['work_time'],
            "pet_notes": item['pet_note'],
            "label": item['label'],
            "employee_notes": item['employee_note'],
            "room_area": item['room_area'],
            "premium_service": item['premium_service'],
            "paymentMethods": item['payment_methods'],
            "order_status": item['order_status'],
            "workingDay": item['working_day'],
            "price": item['price'],
            "accept_job_count": item['accept_job_count']
        }

        result_json.append(result_item)

    return (JSONResponse(content={"wait_confirmation": result_json, "status": "OK"},
                         media_type="application/json; charset=UTF-8"))

@app.put("/partner/put-waiting-job/")
async def put_waiting_job(id: str, db: Session = Depends(get_database)):

    update_query = update(AcceptJob).where(AcceptJob.id == id).values(status=0)
    await db.execute(update_query)
    return {"detail": "OK"}

@app.get("/partner/get-determined/")
async def get_determined(current_user: dict = Depends(verify_jwt_token), db: Session = Depends(get_database)):
    user = await get_partner(db, current_user["sub"])
    print(user['id'])
    sql_query = f'''
      SELECT 
        id.id AS idID,
        id.lat,
        id.lng,
        id.location,
        id.location2,
        i.label,
        i.repeat,
        i.duration,
        id.number_sessions,
        i.repeat_state,
        id.work_time,
        id.pet_note,
        id.employee_note,
        id.room_area,
        id.premium_service,
        id.order_status,
        id.working_day,
        id.price,
        id.payment_methods
    FROM invoice_details id 
    LEFT JOIN invoice i ON id.id_invoice = i.id
    WHERE id.order_status = 3
    and id.id_partner = :id
        '''

    # Execute the SQL query
    filtered_data = await db.fetch_all(sql_query, values={"id": user['id']})

    result_json = []

    for item in filtered_data:
        # Check each field to ensure the value is not null before adding to result_json
        result_item = {
            "idID": item['idID'],
            "lat": item['lat'],
            "lng": item['lng'],
            "location": item['location'],
            "location2": item['location2'],
            "work_time": item['work_time'],
            "pet_notes": item['pet_note'],
            "label": item['label'],
            "repeatState": item['repeat_state'],
            "numberSessions": item['number_sessions'],
            "duration": item['duration'],
            "repeat": item['repeat'],
            "employee_notes": item['employee_note'],
            "room_area": item['room_area'],
            "premium_service": item['premium_service'],
            "order_status": item['order_status'],
            "workingDay": item['working_day'],
            "payment_methods": item['payment_methods'],
            "price": item['price']
        }

        result_json.append(result_item)

    return (JSONResponse(content={"get_determined": result_json, "status": "OK"},
                         media_type="application/json; charset=UTF-8"))




@app.get("/partner/get-calendar/")
async def get_calendar(current_user: dict = Depends(verify_jwt_token), db: Session = Depends(get_database)):
    user = await get_partner(db, current_user["sub"])
    sql_query = f'''
      SELECT 
        id.id AS idID,
        i.id_users AS idU,
        id.lat,
        id.lng,
        id.location,
        id.location2,
        i.label,
        id.work_time,
        id.pet_note,
        id.employee_note,
        id.room_area,
        id.premium_service,
        id.order_status,
        id.working_day,
        id.price,
        id.name_user,
        id.phone_number,
        id.payment_methods
    FROM invoice_details id 
    LEFT JOIN invoice i ON id.id_invoice = i.id
    WHERE id.order_status IN (3, 4)
    and id.id_partner = :id
    AND substr(substr(working_day, INSTR(working_day, ', ') + 2), 7) || '-' || substr(substr(working_day, INSTR(working_day, ', ') + 2), 4, 2) || '-' || substr(substr(working_day, INSTR(working_day, ', ') + 2), 1, 2) BETWEEN :start_date AND :end_date;
        '''

    today = datetime.now().date()  # Lấy ngày hiện tại
    start_date = today
    start_dates = today

    # Format lại ngày bắt đầu và kết thúc theo "DD/MM/YYYY"
    formatted_date_start = start_date.strftime("%Y-%m-%d")

    end_date = today + timedelta(days=6)

    # Format lại ngày kết thúc theo "DD/MM/YYYY"
    formatted_date_end = end_date.strftime("%Y-%m-%d")

    # Thực thi truy vấn SQL
    filtered_data = await db.fetch_all(sql_query, values={"id": user['id'], "start_date": formatted_date_start, "end_date": formatted_date_end})

    # Tạo một danh sách để lưu trữ các mục cho mỗi ngày trong tuần
    result_json = []

    # Khởi tạo một từ điển để lưu trữ thông tin cho mỗi ngày
    days_dict = {
        "Thứ 2": {"firstDay": None, "Day": "Thứ 2", "jobSalary": 0, "jobs": []},
        "Thứ 3": {"firstDay": None, "Day": "Thứ 3", "jobSalary": 0, "jobs": []},
        "Thứ 4": {"firstDay": None, "Day": "Thứ 4", "jobSalary": 0, "jobs": []},
        "Thứ 5": {"firstDay": None, "Day": "Thứ 5", "jobSalary": 0, "jobs": []},
        "Thứ 6": {"firstDay": None, "Day": "Thứ 6", "jobSalary": 0, "jobs": []},
        "Thứ 7": {"firstDay": None, "Day": "Thứ 7", "jobSalary": 0, "jobs": []},
        "Chủ Nhật": {"firstDay": None, "Day": "Chủ Nhật", "jobSalary": 0, "jobs": []}
    }
    for day_info in days_dict.values():

        day_info["firstDay"] = start_date.strftime("%d/%m")  # Gán giá trị cho trường "firstDay"
        # Convert start_date to a string in the format "Y-m-d"
        start_date_str = start_date.strftime("%Y-%m-%d")

        # Convert start_date_str back to a datetime.date object
        start_date_date = datetime.strptime(start_date_str, "%Y-%m-%d").date()
        # Get the weekday string
        weekday_str = get_weekday_string(start_date_date)

        day_info["Day"] = weekday_str

        result_json.append(day_info)

        # Di chuyển ngày khởi đầu sang ngày tiếp theo
        start_date += timedelta(days=1)
    for item in filtered_data:
        # Xác định ngày làm việc
        chuoi_ngay = item['working_day']

        # Tách phần ngày và tháng từ chuỗi
        ngay_va_thang_str = chuoi_ngay.split(", ")[1]

        # Chuyển đổi chuỗi thành đối tượng datetime
        ngay_va_thang_datetime = datetime.strptime(ngay_va_thang_str, "%d/%m/%Y")

        # Chuyển đổi đối tượng datetime thành chuỗi với định dạng mong muốn
        ngay_va_thang_format = ngay_va_thang_datetime.strftime("%Y-%m-%d")
        start_date_date = datetime.strptime(ngay_va_thang_format, "%Y-%m-%d").date()
        #print(start_date_date)
        # Tạo một từ điển để lưu trữ thông tin của công việc
        # Tạo một từ điển để lưu trữ thông tin của công việc
        job_dict = {
            "idID": item['idID'],
            "idU": item['idU'],
            "lat": item['lat'],
            "lng": item['lng'],
            "location": item['location'],
            "location2": item['location2'],
            "work_time": item['work_time'],
            "pet_notes": item['pet_note'],
            "label": item['label'],
            "employee_notes": item['employee_note'],
            "room_area": item['room_area'],
            "premium_service": item['premium_service'],
            "order_status": item['order_status'],
            "price": item['price'],
            "name_user": item['name_user'],
            "payment_methods": item['payment_methods'],
            "workingDay": item['working_day'],
            "phoneNumber": item['phone_number']
        }
        print(get_week_string(start_date_date))
        # Tăng số lượng công việc cho ngày đó
        result_json[get_week_string(start_date_date)]["jobSalary"] += 1
        # Thêm thông tin công việc vào danh sách công việc của ngày đó
        result_json[get_week_string(start_date_date)]["jobs"].append(job_dict)

    # Chuyển đổi từ danh sách từ điển thành danh sách

    return JSONResponse(content={"calendar": result_json, "status": "OK"},
                        media_type="application/json; charset=UTF-8")

@app.put("/partner/put-complete/")
async def put_complete(id: str, db: Session = Depends(get_database)):
    update_queryy = update(InvoiceDetails).where(InvoiceDetails.id == id).values(order_status=4)
    await db.execute(update_queryy)
    return {"detail": "OK"}

@app.get("/partner/get-3clean-wallet/")
async def get_3clean_wallet(current_user: dict = Depends(verify_jwt_token), db: Session = Depends(get_database)):

    user = await get_partner(db, current_user["sub"])
    sql_query = f'''
  select 
bf.id, 
p.money AS moneyP, 
bf.money AS moneyBF, 
bf.note, 
bf.date, 
bf.wallet,
bf.status 
from partner p
left join balance_fluctuations bf on p.id= bf.id_customer 
 where p.id =:id
ORDER BY 
        strftime('%Y-%m-%d %H:%M:%S', bf.date) DESC;
               '''

    # Execute the SQL query
    filtered_data = await db.fetch_all(sql_query,  values={"id": user["id"]})

    result_json = {}
    wallet=[]
    if filtered_data:
        item = filtered_data[0]
        result_json = {
            "moneyP": item['moneyP'],
            'wallet':wallet,

        }
        for item in filtered_data:
            if item['id'] is not None:
                wallet.append({
                    "id": item['id'],
                    "moneyBF": item['moneyBF'],
                    "note": item['note'],
                    "date": item['date'],
                    "wallet": item['wallet'],
                    "status": item['status'],
                })

    return (JSONResponse(content={"3clean_wallet": result_json, "status": "OK"},
                         media_type="application/json; charset=UTF-8"))

@app.post("/partner/bo-cong-viec/", response_model=Message)
async def bo_cong_viec(idID:str, current_user: dict = Depends(verify_jwt_token), db: Session = Depends(get_database)):
    user = await get_partner(db, current_user["sub"])

    idLBCV = "LBCV-" + random_id()

    print(idID)

    async with db.transaction():
        await db.execute(LoaiBoCV.__table__.insert().values(
            id=idLBCV,
            id_invoice_details=idID,
            id_partner=user['id']
        ))

    return Message(detail=0)
@app.get("/partner/lich-su-cong-viec/", response_model=Message)
async def lich_su_cong_viec(current_user: dict = Depends(verify_jwt_token), db: Session = Depends(get_database)):
    user = await get_partner(db, current_user["sub"])
    sql_query = f'''
      SELECT 
        id.location,
        id.location2,
        i.label,
        id.work_time,
        id.working_day,
        id.cancel_job,
        id.reason_cancellation,
        id.cancellation_time_completed,
        id.order_status
    FROM invoice_details id
    LEFT JOIN invoice i ON id.id_invoice = i.id
    WHERE id.order_status IN (0, 5, 6)
    and id.id_partner = :id
    ORDER BY 
            strftime('%Y-%m-%d %H:%M:%S', id.cancellation_time_completed) DESC;
                   '''

    # Execute the SQL query
    filtered_data = await db.fetch_all(sql_query, values={"id": user["id"]})

    # Tạo một từ điển chứa dữ liệu trả về
    result_json = []

    for item in filtered_data:
        titleHuy = "Khách hàng"
        formatted_date_string="None"
        if user['id'] == item['cancel_job']:
            titleHuy = "Bạn"
        original_date_string = item['cancellation_time_completed']
        print(original_date_string)
        if original_date_string is not None:
            # Phân tích chuỗi thành đối tượng datetime
            cleaned_date_string = original_date_string.split('.')[0]

            # Phân tích chuỗi thành đối tượng datetime
            original_datetime = datetime.strptime(cleaned_date_string, "%Y-%m-%d %H:%M:%S")

            # Định dạng lại đối tượng datetime theo định dạng mong muốn
            formatted_date_string = original_datetime.strftime("%H:%M:%S %d/%m/%Y")
        # Check each field to ensure the value is not null before adding to result_json
        result_item = {
            "location": item['location'],
            "location2": item['location2'],
            "work_time": item['work_time'],
            "label": item['label'],
            "workingDay": item['working_day'],
            "cancelJob": titleHuy,
            "reasonCancellation": item['reason_cancellation'],
            "cancellationIimeCompleted": formatted_date_string,
            "orderStatus": item['order_status']
        }

        result_json.append(result_item)

    return (JSONResponse(content={"cancel_complete_history": result_json, "status": "OK"},
                         media_type="application/json; charset=UTF-8"))


@app.get("/partner/statistics")
async def get_statistics(
    start_date_1: str, end_date_1: str,
    start_date_2: str, end_date_2: str,
    current_user: dict = Depends(verify_jwt_token),
    db: Session = Depends(get_database)
):
    user = await get_partner(db, current_user["sub"])

    # Convert string input to datetime objects
    try:
        start_datetime_1 = datetime.strptime(start_date_1, '%Y-%m-%d %H:%M:%S')
        end_datetime_1 = datetime.strptime(end_date_1, '%Y-%m-%d %H:%M:%S')
        start_datetime_2 = datetime.strptime(start_date_2, '%Y-%m-%d %H:%M:%S')
        end_datetime_2 = datetime.strptime(end_date_2, '%Y-%m-%d %H:%M:%S')
    except ValueError:
        raise HTTPException(status_code=400, detail="Invalid date format. Use YYYY-MM-DD HH:MM:SS.")

    sql_query = '''
                SELECT 
                    COUNT(*) AS vcdl,
                    SUM(id.price) AS price,
                    COUNT(CASE WHEN e.star > 2 THEN 1 ELSE NULL END) AS blt,
                    COUNT(CASE WHEN e.star < 2 THEN 1 ELSE NULL END) AS blx
                FROM 
                    Partner p
                INNER JOIN 
                    Invoice_details id ON p.id = id.id_partner
                INNER JOIN 
                    evaluate e ON e.id_partner = p.id
                WHERE 
                    id.id_partner = :id_partner
                    AND id.order_status = 6
                    AND id.cancellation_time_completed BETWEEN :start_date AND :end_date
                    AND e.date BETWEEN :start_date AND :end_date;
               '''

    # Execute the first SQL query
    filtered_data_1 = await db.fetch_all(sql_query, values={"id_partner": user['id'], "start_date": start_datetime_1, "end_date": end_datetime_1})

    # Execute the second SQL query
    filtered_data_2 = await db.fetch_all(sql_query, values={"id_partner": user['id'], "start_date": start_datetime_2, "end_date": end_datetime_2})

    result_json = [
       {
            "vcdl": filtered_data_1[0]['vcdl'] if filtered_data_1 else 0,
            "price": filtered_data_1[0]['price'] if filtered_data_1 else 0,
            "blt": filtered_data_1[0]['blt'] if filtered_data_1 else 0,
            "blx": filtered_data_1[0]['blx'] if filtered_data_1 else 0
        },
       {
            "vcdl": filtered_data_2[0]['vcdl'] if filtered_data_2 else 0,
            "price": filtered_data_2[0]['price'] if filtered_data_2 else 0,
            "blt": filtered_data_2[0]['blt'] if filtered_data_2 else 0,
            "blx": filtered_data_2[0]['blx'] if filtered_data_2 else 0
        }
    ]


    return JSONResponse(content={"statistics":result_json, "status": "OK"}, media_type="application/json; charset=UTF-8")


@app.websocket("/ws")
async def websocket_endpoint(websocket: WebSocket, db: Session = Depends(get_database)):
    await websocket.accept()
    clients.append(websocket)
    try:
        while True:
            try:
                message = await websocket.receive_text()
                await save_message_to_database(message, db)
                for client in clients:
                    if client.application_state == WebSocketState.CONNECTED:
                        print(message)
                        await client.send_text(message)
            except WebSocketDisconnect:
                print(f"Client {websocket.client} disconnected")
                break
            except Exception as e:
                print(f"Error receiving message: {e}")
                break
    except Exception as e:
        print(f"Error in WebSocket connection: {e}")
    finally:
        if websocket in clients:
            clients.remove(websocket)


async def save_message_to_database(message: str, db):
    try:
        idTN = "TN-" + random_id()
        data = json.loads(message)

        # Bắt đầu một phiên giao dịch
        async with db.transaction():
            await db.execute(
                TinNhan.__table__.insert().values(
                    id=idTN,
                    id_nguoi_gui=data['id_nguoi_gui'],
                    id_phong_chat=data['id_phong_chat'],
                    noi_dung=data['noi_dung'],
                    thoi_gian=data['thoi_gian']
                )
            )
            await db.execute(
                update(PhongChat).where(PhongChat.id == data['id_phong_chat']).values(
                    tin_nhan_cuoi_cung=data['noi_dung'],
                    thoi_gian=data['thoi_gian']
                )
            )
    except Exception as e:
        print(f"Error saving message to database: {e}")

@app.get("/get-chat", response_model=Message)
async def get_chat(id: str, db: Session = Depends(get_database)):
    query = """
        SELECT * FROM tin_nhan 
        WHERE id_phong_chat = :id
        ORDER BY thoi_gian ASC;
    """
    db_messages = await db.fetch_all(query, values={"id": id})

    messages = [dict(row) for row in db_messages]

    response_data = {"messages": messages, "status": "OK"}
    return JSONResponse(content=response_data, media_type="application/json; charset=UTF-8")
@app.get("/get-phong-chat/", response_model=Message)
async def get_chat(current_user: dict = Depends(verify_jwt_token), db: Session = Depends(get_database)):
    user = await get_users(db, current_user["sub"])

    query = """
        WITH UserChats AS (
    SELECT 
        tvc.id_phong_chat AS idPC
    FROM thanh_vien_chat tvc 
    WHERE tvc.id_user = :id
)
SELECT 
    tvc.id AS idTVC,
    tvc.id_user AS idU,
    u.image,
    u.name AS nameU,
    u.phoneNumber,
    u.one_star,
    u.two_star,
    u.three_star,
    u.four_star,
    u.five_star,
    tvc.id_phong_chat AS idPC,
    tvc.da_doc,
    pt.tin_nhan_cuoi_cung,
    pt.thoi_gian AS TGNT,
    pt.thoi_gian_tao_phong AS TGTP
FROM thanh_vien_chat tvc
INNER JOIN phong_chat pt ON pt.id = tvc.id_phong_chat
INNER JOIN partner u ON tvc.id_user = u.id
WHERE tvc.id_phong_chat IN (SELECT idPC FROM UserChats)
AND tvc.id_user != :id
ORDER BY pt.thoi_gian DESC;


    """
    db_messages = await db.fetch_all(query, values={"id": user['id']})

    messages = [dict(row) for row in db_messages]

    response_data = {"phong-chat": messages, "status": "OK"}
    return JSONResponse(content=response_data, media_type="application/json; charset=UTF-8")
@app.get("/partner/get-phong-chat/", response_model=Message)
async def get_chat(current_user: dict = Depends(verify_jwt_token), db: Session = Depends(get_database)):
    user = await get_partner(db, current_user["sub"])

    query = """
        WITH UserChats AS (
    SELECT 
        tvc.id_phong_chat AS idPC
    FROM thanh_vien_chat tvc 
    WHERE tvc.id_user = :id
)
SELECT 
    tvc.id AS idTVC,
    tvc.id_user AS idU,
    u.image,
    u.name AS nameU,
    u.phoneNumber,
    tvc.id_phong_chat AS idPC,
    tvc.da_doc,
    pt.tin_nhan_cuoi_cung,
    pt.thoi_gian AS TGNT,
    pt.thoi_gian_tao_phong AS TGTP
FROM thanh_vien_chat tvc
INNER JOIN phong_chat pt ON pt.id = tvc.id_phong_chat
INNER JOIN users u ON tvc.id_user = u.id
WHERE tvc.id_phong_chat IN (SELECT idPC FROM UserChats)
AND tvc.id_user != :id
ORDER BY pt.thoi_gian DESC;

    """
    db_messages = await db.fetch_all(query, values={"id": user['id']})

    messages = [dict(row) for row in db_messages]

    response_data = {"phong-chat": messages, "status": "OK"}
    return JSONResponse(content=response_data, media_type="application/json; charset=UTF-8")

@app.post("/create-chat", response_model=Messageid)
async def create_chat(id_user: str, current_user: dict = Depends(verify_jwt_token),
                      db: Session = Depends(get_database)):
    # Kiểm tra xem hai người dùng đã có chung phòng chat chưa
    user_id = ""
    if id_user[0] == "K":
        user = await get_partner(db, current_user["sub"])
        user_id = user['id']

    else:
        user = await get_users(db, current_user["sub"])
        user_id = user['id']

    query = """
            SELECT phong_chat.id 
            FROM phong_chat 
            JOIN thanh_vien_chat AS tv1 ON phong_chat.id = tv1.id_phong_chat 
            JOIN thanh_vien_chat AS tv2 ON phong_chat.id = tv2.id_phong_chat 
            WHERE tv1.id_user = :user_id AND tv2.id_user = :id_user
        """
    result = await db.fetch_one(query, {"user_id": user_id, "id_user": id_user})

    if result:
        existing_chat = result["id"]
        return Messageid(detail=-1, id = existing_chat)

    # Tạo phòng chat mới
    id_pc = "PC-" + random_id()
    current_datetime = datetime.now()
    formatted_datetime = current_datetime.strftime("%d/%m/%Y %H:%M:%S")
    id_tvc1 = "TVC-" + random_id()
    id_tvc2 = "TVC-" + random_id()
    async with db.transaction():

        # tạo phòng chat
        await db.execute(PhongChat.__table__.insert().values(
            id=id_pc,
            tin_nhan_cuoi_cung="",
            thoi_gian="",
            thoi_gian_tao_phong=formatted_datetime
        ))

        # Thêm hai người dùng vào phòng chat mới
        await db.execute(ThanhVienChat.__table__.insert().values(
            id=id_tvc1,
            id_user=user_id,
            id_phong_chat=id_pc,
            da_doc=0
        ))
        await db.execute(ThanhVienChat.__table__.insert().values(
            id=id_tvc2,
            id_user=id_user,
            id_phong_chat=id_pc,
            da_doc=0
        ))

    return Messageid(detail=0, id=id_pc)

