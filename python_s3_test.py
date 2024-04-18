import boto3
import os
import hashlib
from minio import Minio

def create_file(path, size):
    with open(path, "w") as f:
        f.write("x" * size)

def get_md5(path):
    return hashlib.md5(open(path,'rb').read()).hexdigest()

def upload_download(s3, path, size):
    create_file(path, size=size)
    org_md5 = get_md5(path)
    s3.upload_file(path, BUCKET, path)
    with open(path, "rb") as f:
        s3_client.put_object(Body=f, Bucket=BUCKET, Key=path)

    os.remove(path)
    s3_client.download_file(BUCKET, path, path)
    aft_md5 = get_md5(path)
    assert aft_md5 == org_md5
    os.remove(path)
    r = s3_client.get_object(Bucket=BUCKET, Key=path)
    contents = r['Body'].read()
    # print(contents)


ENDPOINT = "localhost:80"
AWS_ACCESS_KEY_ID="minioadmin"
AWS_SECRET_ACCESS_KEY="minioadmin"
BUCKET = "test-bucket"

session = boto3.session.Session()
s3_client = session.client(
    service_name='s3',
    aws_access_key_id=AWS_ACCESS_KEY_ID,
    aws_secret_access_key=AWS_SECRET_ACCESS_KEY,
    endpoint_url="http://" + ENDPOINT,
)

# list bucket
r = s3_client.list_buckets()
print(r.get('Buckets'))

# upload file - small file
upload_download(s3_client, "file-1k", 1024)
r = s3_client.generate_presigned_url(
    "get_object",
    Params={'Bucket': BUCKET, 'Key': "file-1k"},
    ExpiresIn=600)
print(r)

client = Minio(ENDPOINT, AWS_ACCESS_KEY_ID, AWS_SECRET_ACCESS_KEY, secure=False)
r = client.presigned_get_object(bucket_name=BUCKET, object_name="file-1k")
print(r)