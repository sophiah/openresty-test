import boto3
import os
import hashlib
from minio import Minio
import requests
from botocore.config import Config

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
    assert contents.decode("utf-8") == "x" * size
    # print(contents)


ENDPOINT = "localhost:80"
AWS_ACCESS_KEY_ID="minioadmin"
AWS_SECRET_ACCESS_KEY="minioadmin"
BUCKET = "test-bucket"

OBJECT_NAME = "test-object-dest"

session = boto3.session.Session()
s3_client = session.client(
    service_name='s3',
    aws_access_key_id=AWS_ACCESS_KEY_ID,
    aws_secret_access_key=AWS_SECRET_ACCESS_KEY,
    endpoint_url="http://" + ENDPOINT,
    config=Config(signature_version='s3v4')
)

# list bucket
r = s3_client.list_buckets()
assert BUCKET in [x['Name'] for x in r.get('Buckets')], "list_bucket test fail"

# upload file - small file
test_size = 1024
upload_download(s3_client, OBJECT_NAME, test_size)

r = s3_client.list_objects(Bucket=BUCKET)
print(r)

s3_client.put_object_tagging(
    Bucket=BUCKET,
    Key=OBJECT_NAME,
    Tagging={
        'TagSet': [
            {'Key': 'k1','Value': 'k1v'},
        ]
    },
)

r = s3_client.get_object_tagging(Bucket=BUCKET, Key=OBJECT_NAME)
assert r.get('TagSet') == [{'Key': 'k1', 'Value': 'k1v'}]

rurl = s3_client.generate_presigned_url(
    "get_object",
    Params={'Bucket': BUCKET, 'Key': OBJECT_NAME},
    ExpiresIn=600)
r = requests.get(rurl)
assert r.status_code == 200
assert r.text == "x" * test_size, "boto3.generate_presigned_url test fail"

client = Minio(ENDPOINT, AWS_ACCESS_KEY_ID, AWS_SECRET_ACCESS_KEY, secure=False)
rurl = client.presigned_get_object(bucket_name=BUCKET, object_name=OBJECT_NAME)
r = requests.get(rurl)
assert r.status_code == 200
assert r.text == "x" * test_size, "minio.presigned_get_object test fail"