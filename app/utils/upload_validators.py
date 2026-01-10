import os
import magic
from django.core.exceptions import ValidationError

ALLOWED_EXTENSIONS = {'.jpg', '.jpeg', '.png', '.mp4', '.mov', '.avi'}
ALLOWED_MIME_PREFIX = ('image/', 'video/')

def validate_total_size(files, max_mb=50):
    total = sum(f.size for f in files)
    if total > max_mb * 1024 * 1024:
        raise ValidationError(f"Total upload exceeds {max_mb} MB")

def validate_file(file, allowed=('image/', 'video/'), max_mb=20):
    ext = os.path.splitext(file.name)[1].lower()
    if ext not in ALLOWED_EXTENSIONS:
        raise ValidationError(f"{file.name}: invalid file extension")

    header = file.read(4096)
    file.seek(0)

    mime = magic.from_buffer(header, mime=True)
    if not mime.startswith(ALLOWED_MIME_PREFIX):
        raise ValidationError(f"{file.name}: invalid file type")

    return mime
