#!/usr/bin/env python3

import boto3
import sys

if __name__ == "__main__":

    if len(sys.argv) != 3:
        print(f"Usage: python {sys.argv[0]} <local_file_base_name> <s3_bucket_name>")
        sys.exit(1)

    srcfile = sys.argv[1]
    bucket = sys.argv[2]

    try:
        s3_client = boto3.client('s3')
        s3_client.upload_file(srcfile, bucket, srcfile)
        print(f"File '{srcfile}' uploaded to '{bucket}/{srcfile}'")

    except Exception as e:
        print(f"Error uploading file: {e}")
        sys.exit(1)
