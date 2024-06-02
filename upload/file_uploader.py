import os
from uuid import uuid4
from fastapi import UploadFile

class FileUploader:
    def __init__(self, upload_dir):
        self.upload_dir = upload_dir

    async def upload_file(self, file: UploadFile):
        try:
            # Tạo một tên file duy nhất
            file_name = f"{uuid4()}{os.path.splitext(file.filename)[1]}"
            file_path = os.path.join(self.upload_dir, file_name)

            # Lưu file lên server
            with open(file_path, "wb") as buffer:
                buffer.write(await file.read())

            return {"file_path": file_path}
        except Exception as e:
            return {"error": str(e)}
