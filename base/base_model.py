from pydantic import BaseModel


class Message(BaseModel):
    detail: int

class ChangePassword(BaseModel):
    old_password: str
    new_password: str
    enter_the_password: str

class AdminAvatar(BaseModel):
    image: str
    phonenumber: str

class AdminEmail(BaseModel):
    email: str

class OTPCreate(BaseModel):
    email: str
class OTPUserCreate(BaseModel):
    email: str
    name: str

class OTPVerify(BaseModel):
    email: str
    otp: str

class ResetPassword(BaseModel):
    email: str
    new_password: str

class ServiceCreate(BaseModel):
    id: str
    name: str
    icon: str
    label: int
    status: int

class ServiceUpdate(BaseModel):
    id: str
    status: int

class ServiceAllUpdate(BaseModel):
    id: str
    name: str
    icon: str

class ServiceDurationCreate(BaseModel):
    time: int
    acreage: str
    room: str
    money: int
    status: int

class ServiceUpdateStatus(BaseModel):
    id: str
    status: int

class ServiceDurationUpdate(BaseModel):
    id: str
    time: int
    acreage: str
    room: str
    money: int

class UsersCreate(BaseModel):
    password: str
    phoneNumber: str
    email: str
    name: str
    sex: int
    datebirth: str
    referralCode:str

class CustomerPromotionsCreate(BaseModel):
    id: str

class GCoinUpdale(BaseModel):
    gCoin: str

class RequestEmail(BaseModel):
    email: str


class ForgotPassword(BaseModel):
    email: str
    newPassword: str

class ReferralCode(BaseModel):
    referralCode: str

class CreateLocation(BaseModel):
    location: str
    location2: str
    lat: str
    lng: str

class DeleteLoccation(BaseModel):
    id: str
    defaultt: int

class DeleteSlides(BaseModel):
    id: str

class UpdateLoccation(BaseModel):
    id: str
    id_users: str

class CreatePromotion(BaseModel):
    id: str
    name: str
    code: str
    start_day: str
    end_day: str
    content: str
    label: int
    discount: int
    point: int

class UpdatePromotion(BaseModel):
    id: str
    name: str
    code: str
    start_day: str
    end_day: str
    content: str
    label: int
    discount: int
    point: int

class SelectPromotionId(BaseModel):
    id: str

class CreateSlide(BaseModel):
    id:str
    imageUrl: str
    newsUrl: str

class UpdateSlide(BaseModel):
    id:str
    imageUrl: str
    newsUrl: str

class DeleteSlide(BaseModel):
    id: str

class CreateBlog(BaseModel):
    id: str
    imageUrl: str
    newsUrl: str
    title: str
    content: str

class UpdateBlog(BaseModel):
    id: str
    imageUrl: str
    newsUrl: str
    title: str
    content: str

class UpdateBlogStatus(BaseModel):
    id: str
    status: int

class CreateInvoice(BaseModel):
    idP: str
    label: int
    nameUser: str
    phoneNumber: str
    location: str
    location2: str
    lat: str
    lng: str
    repeat: str
    petNote: str
    employeeNote: str
    note: str
    workingDay: str
    workTime: str
    roomArea: str
    price: int
    gPoints: int
    paymentMethods: int
    repeat_state: int
    premium_service: int

class SelectJobDetails(BaseModel):
    id: str

class CreatePartner(BaseModel):
    email: str
    phonenumber: str
    password: str
    name: str
    service: str
    image: str
    datebirth: str
    cccd: str
    date_cccd: str
    address: str
    sex: int

class CreateWallet(BaseModel):
    price: int
    money: int
    note: str
    wallet: str
    status: int

class CreateWalletU(BaseModel):
    money: int
    note: str
    wallet: str
    status: int
    id: str
    idP: str

class CreateDanhGia(BaseModel):
    idP: str
    idID: str
    sao: int
    note: str
