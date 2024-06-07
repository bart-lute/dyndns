#!/usr/bin/env python
import logging
import os
import secrets
from typing import Annotated

import boto3
import uvicorn
from dotenv import load_dotenv
from fastapi import FastAPI, Request, Response, Depends, HTTPException, status
from fastapi.security import HTTPBasic, HTTPBasicCredentials

logger = logging.getLogger("uvicorn.info")

app = FastAPI()
security = HTTPBasic()


def authorize(credentials: Annotated[HTTPBasicCredentials, Depends(security)]):
    current_username_bytes = credentials.username.encode("utf8")
    correct_username_bytes = bytes(os.getenv("USERNAME").encode("utf8"))
    is_correct_username = secrets.compare_digest(
        current_username_bytes, correct_username_bytes
    )
    current_password_bytes = credentials.password.encode("utf8")
    correct_password_bytes = bytes(os.getenv("PASSWORD").encode("utf8"))
    is_correct_password = secrets.compare_digest(
        current_password_bytes, correct_password_bytes
    )
    if not (is_correct_username and is_correct_password):
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Incorrect username or password",
            headers={"WWW-Authenticate": "Basic"},
        )
    return credentials.username


def update_rout53(ip: str, host: str):
    logger.info(f"Updating Route53 with IP: {ip}, Host: {host}...")
    client = boto3.client("route53")
    response = client.change_resource_record_sets(
        HostedZoneId=os.getenv("HOSTED_ZONE_ID"),
        ChangeBatch={
            "Changes": [
                {
                    "Action": "UPSERT",
                    "ResourceRecordSet": {
                        "Name": host,
                        "Type": "A",
                        "TTL": 60,
                        "ResourceRecords": [{"Value": ip}],
                    },
                }
            ],
            "Comment": "Updated by inadyn",
        },
    )
    if response["ResponseMetadata"]["HTTPStatusCode"] == 200:
        return f"ok {ip}"
    return f"fail {ip}"


@app.get("/updatedns")
async def root(request: Request, ip: str, host: str, username: Annotated[str, Depends(authorize)]):
    logger.info(f"Updating DNS with IP: {ip}, Host: {host}")
    return Response(content=update_rout53(ip, host), media_type="text/plain")


if __name__ == "__main__":
    load_dotenv()
    config = uvicorn.Config(
        app="main:app",
        host=os.getenv("HOST"),
        port=int(os.getenv("PORT")),
        log_level="info"
    )
    server = uvicorn.Server(config)
    server.run()