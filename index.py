from config.config import DATABASE_URL
from fastapi import FastAPI, HTTPException, Depends, BackgroundTasks, status
from sqlalchemy import create_engine, select, update, desc, text, func
from sqlalchemy.orm import sessionmaker, Session
from databases import Database
from base.class_base import OTP, Base, Admin, Service, ServiceDuration, Users, Location, Promotion, Slides, Blog, \
    CustomerPromotions, Invoice, InvoiceDetails, AcceptJob, Notification, Partner, BalanceFluctuations
from base.base_model import CreateLocation, ReferralCode, ForgotPassword, RequestEmail, OTPUserCreate, UsersCreate, \
    ServiceDurationUpdate, ServiceUpdateStatus, ServiceDurationCreate, ServiceAllUpdate, ServiceUpdate, Message, \
    ChangePassword, AdminAvatar, OTPCreate, OTPVerify, ResetPassword, AdminEmail, ServiceCreate, DeleteLoccation, \
    UpdateLoccation, CreatePromotion, UpdatePromotion, CreateSlide, CreateBlog, UpdateBlog, DeleteSlides, UpdateSlide, \
    UpdateBlogStatus, SelectPromotionId, CustomerPromotionsCreate, GCoinUpdale, CreateInvoice, SelectJobDetails, \
    CreatePartner, CreateWallet, CreateWalletU
from utils import get_db_location, generate_referral_code, convert_string, get_users, convert_date, \
    get_select_service_duration, get_select_service, delete_otp_after_delay, random_id, create_jwt_token, \
    verify_jwt_token, get_admin, oauth2_scheme, token_blacklist, get_delete_location, get_select_slides, \
    get_select_promotion, get_delete_slide, get_select_blog, current_date, get_select_promotion_id, get_db_user, \
    get_partner, extract_indexes, get_weekday_string, get_partner_id
from mail.otb_email import send_otp_email
from mail.cskh_email import send_cskh_email
import json
from starlette.responses import Response, JSONResponse
from datetime import datetime, timedelta


def get_database():
    database = Database(DATABASE_URL)
    return database

# Kết nối đến cơ sở dữ liệu
engine = create_engine(DATABASE_URL)
Base.metadata.create_all(bind=engine)

# Tạo đối tượng SessionLocal để tương tác với cơ sở dữ liệu
SessionLocal = sessionmaker(autocommit=False, autoflush=False, bind=engine)
app = FastAPI(root_path="/api/v1")

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
async def change_password(change_old_password: ChangePassword, current_user: dict = Depends(verify_jwt_token), db: Session = Depends(get_database)):
    # Lấy thông tin người dùng từ cơ sở dữ liệu
    user = await get_admin(db, current_user["sub"])
    update_new_password = ChangePassword(**change_old_password.dict())

    # Kiểm tra mật khẩu cũ
    if user["password"] != update_new_password.old_password:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail=-1,
        )
    
    # Kiểm tra trùng mật khẩu
    if update_new_password.new_password != update_new_password.enter_the_password:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail=-2,
        )
    
    update_query = update(Admin).where(Admin.id == user['id']).values(
            password=update_new_password.new_password)
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
        
        send_otp_email(new_otp_data.email, otp_code, user['name'])

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
    
    send_otp_email(new_otp_data.email, otp_code, user['name'])

    background_tasks.add_task(delete_otp_after_delay, new_otp_data.email, db)

    return Message(detail=0)

# Đường dẫn để xác minh OTP
@app.post("/verify-otp/",response_model=Message)
async def verify_otp(otp_data: OTPVerify, db: Session = Depends(get_database)):
    print(otp_data.email)
    print(otp_data.otp)
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

# Thông tin admin
@app.get("/admin/select-admin-information/")
async def select_admin_information(current_user: dict = Depends(verify_jwt_token), db: Session = Depends(get_database)):
    # Lấy thông tin người dùng từ cơ sở dữ liệu
    admin = await get_admin(db, current_user["sub"])
    
    # Trả về dữ liệu bảo vệ
    return {"admin_info": admin}


#---------------------------Quản lý tác vụ-------------------------------------------------

# Tạo dịch vụ
@app.post("/admin/create-service/", response_model=Message)
async def create_service(add_service: ServiceCreate, db: Session = Depends(get_database)):
    db_service = Service(**add_service.dict())

    async with db.transaction():
        await db.execute(Service.__table__.insert().values(
            id=db_service.id,
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
    
    update_query = update(Service).where(Service.id == _update.id).values(
            status=_update.status)
    await db.execute(update_query)

    return Message(detail=0)

# Sửa dịch vụ
@app.put("/admin/update-all-service/",response_model=Message)
async def update_all_service(service_update: ServiceAllUpdate, db: Session = Depends(get_database)):
    
    _update = Service(**service_update.dict())
    
    update_query = update(Service).where(Service.id == _update.id).values(
            name=_update.name,
            icon= _update.icon,
            )
    await db.execute(update_query)

    return Message(detail=0)

#---------------------------Quản lý Thời luọng-------------------------------------------------

# Tạo Thời lượng
@app.post("/admin/create-service-duration/", response_model=Message)
async def create_service_duration(add_service_duration: ServiceDurationCreate, db: Session = Depends(get_database)):
    
    id = "TL-" + str(random_id())
    db_service_duration = ServiceDurationCreate(id=id, **add_service_duration.dict())

    async with db.transaction():
        await db.execute(ServiceDuration.__table__.insert().values(
            id=id,
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
async def update_service_duration(service_duration_update: ServiceDurationUpdate, db: Session = Depends(get_database)):
    
    _update = ServiceDurationUpdate(**service_duration_update.dict())
    
    update_query = update(ServiceDuration).where(ServiceDuration.id == _update.id).values(
            time= _update.time,
            acreage= _update.acreage,
            room= _update.room,
            money= _update.money
            )
    await db.execute(update_query)

    return Message(detail=0)




#--------------------------Blog-------------------------
@app.post("/admin/create-blog/", response_model=Message)
async def create_blog(add_blog: CreateBlog, db: Session = Depends(get_database)):

    db_blog = CreateBlog(**add_blog.dict())

    async with db.transaction():
        await db.execute(Blog.__table__.insert().values(
            id=db_blog.id,
            imageUrl=db_blog.imageUrl,
            newsUrl=db_blog.newsUrl,
            title=db_blog.title,
            content=db_blog.content,
            date=current_date,
            status=1
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
async def create_promotion(add_promotion: CreatePromotion, db: Session = Depends(get_database)):

    db_promotion = Promotion(**add_promotion.dict())

    async with db.transaction():
        await db.execute(Promotion.__table__.insert().values(
            id=db_promotion.id,
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
async def update_promotion(promotion_update: UpdatePromotion, db: Session = Depends(get_database)):

    _update = UpdatePromotion(**promotion_update.dict())

    update_query = update(Promotion).where(Promotion.id == _update.id).values(
        name=_update.name,
        code=_update.code,
        start_day=_update.start_day,
        end_day=_update.end_day,
        content=_update.content,
        label=_update.label,
        discount=_update.discount,
        point=_update.point

        )
    await db.execute(update_query)

    return Message(detail=0)





#-------------------------------------Slides-------------------------------------
@app.post("/admin/create-slides/", response_model=Message)
async def create_slide(add_promotion: CreateSlide, db: Session = Depends(get_database)):
    current_date = datetime.now().strftime("%d/%m/%Y")
    db_slide = CreateSlide(**add_promotion.dict())

    async with db.transaction():
        await db.execute(Slides.__table__.insert().values(
            id=db_slide.id,
            imageUrl=db_slide.imageUrl,
            newsUrl=db_slide.newsUrl,
            date=current_date
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

@app.put("admin/update-slides/")
async def update_slide(update_sl: UpdateSlide, db: Session = Depends(get_database)):

    update_slides = update(Slides).where(Slides.id == update_sl.id).values(
        imageUrl=update_sl.imageUrl,
        newsUrl=update_sl.newsUrl
    )
    await  db.execute(update_slides)

    return {"detail": "OK"}



#-----------Users------------------

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
    send_otp_email(new_otp_data.email, otp_code, name)

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

#kiểm trakhuyến mãi
@app.post("/check-customer-promotions/", response_model=Message)
async def check_customer_promotions(add_check_promotions: CustomerPromotionsCreate,current_user: dict = Depends(verify_jwt_token),  db: Session = Depends(get_database)):
    user = await get_users(db, current_user["sub"])

    db_promotions = CustomerPromotionsCreate(**add_check_promotions.dict())

    query = CustomerPromotions.__table__.select().where((CustomerPromotions.id_users == user['id']) & (CustomerPromotions.id_promotion == db_promotions.id))
    service = await db.fetch_one(query)
    if service:
        return Message(detail=0)
    return Message(detail=-1)


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
        (s.status = 1 OR s.id IS NULL)
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
                'label': item['label']
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
            name_user=db_invoice.nameUser,
            phoneNumber=db_invoice.phoneNumber,
            location=db_invoice.location,
            location2=db_invoice.location2,
            lat=db_invoice.lat,
            lng=db_invoice.lng,
            repeat=db_invoice.repeat,
            pet_notes=db_invoice.petNote,
            employee_notes=db_invoice.employeeNote,
            price=db_invoice.price,
            pet_status=db_invoice.petStatus,
            invoice_status=1,
            repeat_state=db_invoice.repeat_state

        ))

        await db.execute(InvoiceDetails.__table__.insert().values(
            id=idIVD,
            id_invoice=idIV,
            id_partner="",
            posting_time=current_datetime,
            working_day=db_invoice.workingDay,
            work_time=db_invoice.workTime,
            room_area=db_invoice.roomArea,
            payment_methods=db_invoice.paymentMethods,
            price=db_invoice.price,
            order_status=1,
            cancel_job="",
            premium_service=db_invoice.premium_service
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

        if db_invoice.paymentMethods==2 :
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
    id.premium_service,
    i.pet_notes, 
    i.employee_notes, 
    i.invoice_status,
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
                "petNotes": item['pet_notes'],
                "employeeNotes": item['employee_notes'],
                "premiumService": item['premium_service'],
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
    id.premium_service,
    i.pet_notes, 
    i.employee_notes, 
    i.invoice_status,
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
and id.order_status IN (0,5)
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
                "petNotes": item['pet_notes'],
                "employeeNotes": item['employee_notes'],
                "premiumService": item['premium_service'],
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

#get thông tin công viêệc chi tiết
@app.get("/get-job-details/")
async def get_job_details(id: str, db: Session = Depends(get_database)):
    sql_query = '''
            SELECT 
            id.id AS idIVD, 
            i.id AS idIV, 
            p.id AS idP,
            id.id_partner AS idPT,
            u.name AS nameU,
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
            "label": item['label'],
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


# Tao tai khoan doi tac
class CreateWall:
    pass


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
        e.date
     from partner p 
     left join evaluate e on p.id=e.id_parther 
     left join users u on e.id_user = u.id
    where p.id =:id
        '''

    # Execute the SQL query
    filtered_data = await db.fetch_all(sql_query, values={"id": id})

    result_json = []

    for item in filtered_data:
        user_info = []
        if item['idE'] is not None:
            user_info.append({
                "idE": item['idE'],
                "nameU": item['nameU'],
                "imageU": item['imageU'],
                "content": item['content'],
                "date": item['date']
            })

        # Check each field to ensure the value is not null before adding to result_json
        result_item = {
            "idP": item['idP'],
            "idE": item['idE'],
            "nameP": item['nameP'],
            "imageP": item['imageP'],
            "oneStar":item['oneStarP'],
            "twoStar":item['twoStarP'],
            "threeStar":item['threeStarP'],
            "fourStar":item['fourStarP'],
            "fiveStar":item['fiveStarP'],
            "user": user_info
        }

        result_json.append(result_item)

    return (JSONResponse(content={"partner_information": result_json, "status": "OK"},
                         media_type="application/json; charset=UTF-8"))

@app.put("/put-cancel-job/")
async def put_cancel_job(order_status: int, stt: int, price: int, idInvoiceDetails: str, current_user: dict = Depends(verify_jwt_token), db: Session = Depends(get_database)):

    if stt == 0:
        user = await get_users(db, current_user["sub"])
        moneys = price + int(user['money'])
        update_queryy = update(InvoiceDetails).where(InvoiceDetails.id == idInvoiceDetails).values(cancel_job=user['id'])
        update_query = update(Users).where(Users.id == id).values(money=moneys)
        await db.execute(update_queryy)
        await db.execute(update_query)
    else:
        user = await get_partner(db, current_user["sub"])
        moneys = price + int(user['money'])
        update_queryy = update(InvoiceDetails).where(InvoiceDetails.id == idInvoiceDetails).values(cancel_job=user['id'])
        update_query = update(Partner).where(Partner.id == id).values(money=moneys)
        await db.execute(update_queryy)
        await db.execute(update_query)
    return {"detail": "OK"}
@app.put("/put-complete/")
async def put_completee(add_create_partner: CreateWalletU,  db: Session = Depends(get_database)):
    current_datetime = datetime.now()
    idBF = "BF-" + random_id()
    print(idBF)
    db_create_wallet = CreateWalletU(**add_create_partner.dict())

    user = await get_partner_id(db, db_create_wallet.idP)

    p = db_create_wallet.money + int(user['money'])

    async with db.transaction():
        await db.execute(update(InvoiceDetails).where(InvoiceDetails.id == db_create_wallet.id).values(order_status=5))

        await db.execute( update(Partner).where(Partner.id == db_create_wallet.idP).values(money=p))

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

# # Hàm lấy thông tin chi tiết của đối tác
# @app.get("/partner/get-partner-details/")
# async def get_partner_details(id: str, db: Session = Depends(get_database)):
#     sql_query = '''
#             SELECT p.id AS idP,
#                p.id_admin,
#                id.id AS idID,
#                bf.id AS idBf,
#                ad.name AS nameAD,
#                u.name AS nameU,
#                p.email,
#                p.phonenumber,
#                p.password,
#                p.name AS nameP,
#                p.one_star,
#                p.two_star,
#                p.three_star,
#                p.four_star,
#                p.five_star,
#                p.image,
#                p.service,
#                p.date_cccd,
#                p.datebirth,
#                p.cccd,
#                p.address,
#                p.sex,
#                p.date,
#                p.money,
#                p.lat,
#                p.lng,
#                bf.status AS statusBF,
#                bf.date AS dateBF,
#                id.posting_time,
#                id.working_day,
#                id.work_time,
#                id.room_area,
#                id.price,
#                id.order_status,
#                id.cancel_job
#         FROM partner p
#         LEFT JOIN admin ad ON p.id_admin = ad.id
#         LEFT JOIN balance_fluctuations bf ON p.id = bf.id_customer
#         LEFT JOIN invoice_details id ON p.id = id.id_partner
#         LEFT JOIN invoice i ON id.id_invoice = i.id
#         LEFT JOIN users u ON i.id_users = u.id
#         where
#         p.id = :id
#     '''
#
#     # Thực thi truy vấn SQL
#     filtered_data = await db.fetch_all(sql_query, values={"id": id})
#     balance_fluctuations_info = []
#     invoice_details_info = []
#
#     # Tạo một danh sách trống để lưu chi tiết công việc
#     result_item = {}
#
#     # Kiểm tra xem dữ liệu có tồn tại không
#     if filtered_data:
#         item = filtered_data[0]  # Lấy bản ghi đầu tiên
#
#         # Tạo thông tin về đối tác
#         result_item = {
#             "idP": item['idP'],
#             "idAdmin": item['id_admin'],
#             "email": item['email'],
#             "phoneNumber": item['phonenumber'],
#             "password": item['password'],
#             "nameP": item['nameP'],
#             "oneStar": item['one_star'],
#             "twoStar": item['two_star'],
#             "threeStar": item['three_star'],
#             "fourStar": item['four_star'],
#             "fiveStar": item['five_star'],
#             "image": item['image'],
#             "service": item['service'],
#             "dateCccd": item['date_cccd'],
#             "dateBirth": item['datebirth'],
#             "cccd": item['cccd'],
#             "address": item['address'],
#             "sex": item['sex'],
#             "date": item['date'],
#             "money": item['money'],
#             "lat": item['lat'],
#             "lng": item['lng'],
#             "balanceFluctuations": balance_fluctuations_info,
#             "invoiceDetails": invoice_details_info
#         }
#
#         # Lặp qua các bản ghi để lấy thông tin về biến động dư cân và chi tiết hóa đơn
#         for item in filtered_data:
#             if item['idBf'] is not None:
#                 balance_fluctuations_info.append({
#                     "idBf": item['idBf'],
#                     "statusBF": item['statusBF'],
#                     "dateBF": item['dateBF']
#                 })
#
#             if item['idID'] is not None:
#                 invoice_details_info.append({
#                     "idID": item['idID'],
#                     "nameU": item['nameU'],
#                     "postingTime": item['posting_time'],
#                     "workingDay": item['working_day'],
#                     "workTime": item['work_time'],
#                     "roomArea": item['room_area'],
#                     "price": item['price'],
#                     "orderStatus": item['order_status'],
#                     "cancelJob": item['cancel_job'],
#                 })
#
#     return JSONResponse(content={"partner_details": result_item, "status": "OK"},
#                         media_type="application/json; charset=UTF-8")

@app.get("/partner/get-job/")
async def get_job(current_user: dict = Depends(verify_jwt_token), db: Session = Depends(get_database)):

    user = await get_partner(db, current_user["sub"])
    result = extract_indexes(user['service'])
    sql_query = f'''
      SELECT 
            id.id,
            i.lat,
            i.lng,
            i.location,
            i.location2,
            i.label,
            id.work_time,
            i.pet_notes,
            i.employee_notes,
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
            "location2": item['location2'],
            "work_time": item['work_time'],
            "pet_notes": item['pet_notes'],
            "label": item['label'],
            "employee_notes": item['employee_notes'],
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
        id.id AS idID,
        aj.id AS idAJ,
        i.lat,
        i.lng,
        i.location,
        i.location2,
        i.label,
        id.work_time,
        i.pet_notes,
        i.employee_notes,
        id.room_area,
        id.premium_service,
        id.order_status,
        id.working_day,
        id.price,
        id.payment_methods,
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
            "idID": item['idID'],
            "idAJ": item['idAJ'],
            "lat": item['lat'],
            "lng": item['lng'],
            "location": item['location'],
            "location2": item['location2'],
            "work_time": item['work_time'],
            "pet_notes": item['pet_notes'],
            "label": item['label'],
            "employee_notes": item['employee_notes'],
            "room_area": item['room_area'],
            "premium_service": item['premium_service'],
            "order_status": item['order_status'],
            "workingDay": item['working_day'],
            "price": item['price'],
            "payment_methods": item['payment_methods'],
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
        i.lat,
        i.lng,
        i.location,
        i.location2,
        i.label,
        id.work_time,
        i.pet_notes,
        i.employee_notes,
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
            "pet_notes": item['pet_notes'],
            "label": item['label'],
            "employee_notes": item['employee_notes'],
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
    print(user['id'])
    sql_query = f'''
      SELECT 
        id.id AS idID,
        i.lat,
        i.lng,
        i.location,
        i.location2,
        i.label,
        id.work_time,
        i.pet_notes,
        i.employee_notes,
        id.room_area,
        id.premium_service,
        id.order_status,
        id.working_day,
        id.price,
        i.name_user,
        i.phoneNumber,
        id.payment_methods
    FROM invoice_details id 
    LEFT JOIN invoice i ON id.id_invoice = i.id
    WHERE id.order_status IN (3, 4)
    and id.id_partner = :id
    and substr(working_day, INSTR(working_day, ', ') + 2) >= :start_date
    and substr(working_day, INSTR(working_day, ', ') + 2) <= :end_date
        '''

    today = datetime.now().date()  # Lấy ngày hiện tại
    start_date = today

    # Format lại ngày bắt đầu và kết thúc theo "DD/MM/YYYY"
    formatted_date_start = start_date.strftime("%d/%m/%Y")
    end_date = today + timedelta(days=6)  # Tính ngày kết thúc

    # Format lại ngày kết thúc theo "DD/MM/YYYY"
    formatted_date_end = end_date.strftime("%d/%m/%Y")

    # Thực thi truy vấn SQL
    filtered_data = await db.fetch_all(sql_query, values={"id": user['id'], "start_date": formatted_date_start, "end_date": formatted_date_end})

    # Tạo một danh sách để lưu trữ các mục cho mỗi ngày trong tuần
    result_json = []

    # Khởi tạo một từ điển để lưu trữ thông tin cho mỗi ngày
    days_dict = {
        "Chủ Nhật": {"firstDay": None, "Day": "Chủ Nhật", "jobSalary": 0, "jobs": []},
        "Thứ 2": {"firstDay": None, "Day": "Thứ 2", "jobSalary": 0, "jobs": []},
        "Thứ 3": {"firstDay": None, "Day": "Thứ 3", "jobSalary": 0, "jobs": []},
        "Thứ 4": {"firstDay": None, "Day": "Thứ 4", "jobSalary": 0, "jobs": []},
        "Thứ 5": {"firstDay": None, "Day": "Thứ 5", "jobSalary": 0, "jobs": []},
        "Thứ 6": {"firstDay": None, "Day": "Thứ 6", "jobSalary": 0, "jobs": []},
        "Thứ 7": {"firstDay": None, "Day": "Thứ 7", "jobSalary": 0, "jobs": []}
    }

    for item in filtered_data:
        # Xác định ngày làm việc
        working_day_str = item['working_day']
        working_day = datetime.strptime(working_day_str.split(', ')[1], '%d/%m/%Y').date()

        # Tạo một từ điển để lưu trữ thông tin của công việc
        job_dict = {
            "idID": item['idID'],
            "lat": item['lat'],
            "lng": item['lng'],
            "location": item['location'],
            "location2": item['location2'],
            "work_time": item['work_time'],
            "pet_notes": item['pet_notes'],
            "label": item['label'],
            "employee_notes": item['employee_notes'],
            "room_area": item['room_area'],
            "premium_service": item['premium_service'],
            "order_status": item['order_status'],
            "price": item['price'],
            "name_user": item['name_user'],
            "payment_methods": item['payment_methods'],
            "workingDay": item['working_day'],
            "phoneNumber": item['phoneNumber']
        }
        # Tăng số lượng công việc cho ngày đó
        days_dict[get_weekday_string(working_day)]["jobSalary"] += 1
        # Thêm thông tin công việc vào danh sách công việc của ngày đó
        days_dict[get_weekday_string(working_day)]["jobs"].append(job_dict)

    # Chuyển đổi từ danh sách từ điển thành danh sách
    for day_info in days_dict.values():
        day_info["firstDay"] = start_date.strftime("%d/%m")  # Gán giá trị cho trường "firstDay"
        result_json.append(day_info)

        # Di chuyển ngày khởi đầu sang ngày tiếp theo
        start_date += timedelta(days=1)

    return JSONResponse(content={"calendar": result_json, "status": "OK"},
                        media_type="application/json; charset=UTF-8")

@app.put("/partner/put-complete/")
async def put_complete(id: str, db: Session = Depends(get_database)):
    update_queryy = update(InvoiceDetails).where(InvoiceDetails.id == id).values(order_status=4)
    await db.execute(update_queryy)
    return {"detail": "OK"}