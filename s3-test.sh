#!/bin/bash

export AWS_ACCESS_KEY_ID=minioadmin
export AWS_SECRET_ACCESS_KEY=minioadmin

# export AWS_ACCESS_KEY_ID=minioadmin
# export AWS_SECRET_ACCESS_KEY=wrong

ENDPOINT=http://localhost:80
BUCKET=test-bucket

curl "${ENDPOINT}/status"

aws s3 --endpoint=${ENDPOINT} ls

# dd if=/dev/zero of=test.obj  bs=1M  count=1
# aws s3 --endpoint=${ENDPOINT} cp test.obj s3://${BUCKET}/t-1M.obj # --debug
# rm test.obj

# dd if=/dev/zero of=test.obj  bs=10M  count=1
# aws s3 --endpoint=${ENDPOINT} cp test.obj s3://${BUCKET}/t-10M.obj # --debug
# rm test.obj

# dd if=/dev/zero of=test.obj  bs=32M  count=1
# aws s3 --endpoint=${ENDPOINT} cp test.obj s3://${BUCKET}/t-32M.obj # --debug
# rm test.obj

aws s3api --endpoint=${ENDPOINT} get-object-tagging --bucket ${BUCKET} --key t-1M.obj

# for i in {0..9}; do
# aws s3 cp --endpoint=${ENDPOINT} s3://${BUCKET}/t-1M.obj t-1M.obj; rm t-1M.obj;
# aws s3 cp --endpoint=${ENDPOINT} s3://${BUCKET}/t-10M.obj t-10M.obj; rm t-10M.obj
# aws s3 cp --endpoint=${ENDPOINT} s3://${BUCKET}/t-32M.obj t-32M.obj; rm t-32M.obj
# done

# aws s3 --endpoint=${ENDPOINT} rm s3://${BUCKET}/t-1M.obj 
# aws s3 --endpoint=${ENDPOINT} rm s3://${BUCKET}/t-10M.obj 
# aws s3 --endpoint=${ENDPOINT} rm s3://${BUCKET}/t-32M.obj 
