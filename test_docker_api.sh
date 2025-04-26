#!/bin/bash

# Base URL
BASE_URL="http://localhost:8000"

echo "Testing PhoneBook API..."
echo "========================"

# Get writer token
echo "1. Getting writer token..."
WRITER_TOKEN=$(curl -s -X POST "${BASE_URL}/token" \
  -H "Content-Type: application/x-www-form-urlencoded" \
  -d "username=writer&password=writerpass" | jq -r '.access_token')
echo "Writer token obtained"

# Get reader token
echo -e "\n2. Getting reader token..."
READER_TOKEN=$(curl -s -X POST "${BASE_URL}/token" \
  -H "Content-Type: application/x-www-form-urlencoded" \
  -d "username=reader&password=readerpass" | jq -r '.access_token')
echo "Reader token obtained"

# Add entry with writer token
echo -e "\n3. Adding new entry with writer token..."
curl -s -X POST "${BASE_URL}/PhoneBook/add" \
  -H "Authorization: Bearer ${WRITER_TOKEN}" \
  -H "Content-Type: application/json" \
  -d '{"name": "Bruce Schneier", "phoneNumber": "(703)111-2121"}'
echo -e "\nEntry added"

# List entries with reader token
echo -e "\n4. Listing entries with reader token..."
curl -s -X GET "${BASE_URL}/PhoneBook/list" \
  -H "Authorization: Bearer ${READER_TOKEN}"
echo -e "\nEntries listed"

# Try to add entry with reader token (should fail)
echo -e "\n5. Trying to add entry with reader token (should fail)..."
curl -s -X POST "${BASE_URL}/PhoneBook/add" \
  -H "Authorization: Bearer ${READER_TOKEN}" \
  -H "Content-Type: application/json" \
  -d '{"name": "Should Fail", "phoneNumber": "123-4567"}'
echo -e "\nAttempt completed"

# Delete entry with writer token
echo -e "\n6. Deleting entry with writer token..."
curl -s -X PUT "${BASE_URL}/PhoneBook/deleteByName?name=Bruce%20Schneier" \
  -H "Authorization: Bearer ${WRITER_TOKEN}"
echo -e "\nEntry deleted"

# Try invalid inputs
echo -e "\n7. Testing invalid inputs..."
curl -s -X POST "${BASE_URL}/PhoneBook/add" \
  -H "Authorization: Bearer ${WRITER_TOKEN}" \
  -H "Content-Type: application/json" \
  -d '{"name": "L33t Hacker", "phoneNumber": "(703)111-2121"}'
echo -e "\nInvalid name test completed"

curl -s -X POST "${BASE_URL}/PhoneBook/add" \
  -H "Authorization: Bearer ${WRITER_TOKEN}" \
  -H "Content-Type: application/json" \
  -d '{"name": "Valid Name", "phoneNumber": "invalid-phone"}'
echo -e "\nInvalid phone test completed"

echo -e "\nAll tests completed!" 