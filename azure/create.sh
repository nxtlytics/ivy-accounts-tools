#!/bin/bash

read -r -p  "Deployment Name? " NAME
read -r -p  "Deployment Region? " REGION

az deployment sub create -c -f ./main.bicep -l "$REGION" -n "$NAME"
