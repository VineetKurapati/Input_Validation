# Base URL
$BASE_URL = "http://localhost:8000"

Write-Host "Testing PhoneBook API..."
Write-Host "========================"

# Get writer token
Write-Host "1. Getting writer token..."
$headers = @{ "Content-Type" = "application/x-www-form-urlencoded" }
$body = "username=writer&password=writerpass"
$writerTokenResponse = Invoke-RestMethod -Method Post -Uri "$BASE_URL/token" -Headers $headers -Body $body
$writerToken = $writerTokenResponse.access_token
Write-Host "Writer token obtained"

# Get reader token
Write-Host "`n2. Getting reader token..."
$body = "username=reader&password=readerpass"
$readerTokenResponse = Invoke-RestMethod -Method Post -Uri "$BASE_URL/token" -Headers $headers -Body $body
$readerToken = $readerTokenResponse.access_token
Write-Host "Reader token obtained"

# Add entry with writer token
Write-Host "`n3. Adding new entry with writer token..."
$headers = @{
    "Authorization" = "Bearer $writerToken"
    "Content-Type" = "application/json"
}
$body = @{
    name = "Bruce Schneier"
    phoneNumber = "(703)111-2121"
} | ConvertTo-Json
$response = Invoke-RestMethod -Method Post -Uri "$BASE_URL/PhoneBook/add" -Headers $headers -Body $body
Write-Host "Response: $($response | ConvertTo-Json)"

# List entries with reader token
Write-Host "`n4. Listing entries with reader token..."
$headers = @{ "Authorization" = "Bearer $readerToken" }
$response = Invoke-RestMethod -Method Get -Uri "$BASE_URL/PhoneBook/list" -Headers $headers
Write-Host "Entries: $($response | ConvertTo-Json)"

# Try to add entry with reader token (should fail)
Write-Host "`n5. Trying to add entry with reader token (should fail)..."
$headers = @{
    "Authorization" = "Bearer $readerToken"
    "Content-Type" = "application/json"
}
$body = @{
    name = "Should Fail"
    phoneNumber = "123-4567"
} | ConvertTo-Json
try {
    $response = Invoke-RestMethod -Method Post -Uri "$BASE_URL/PhoneBook/add" -Headers $headers -Body $body
} catch {
    Write-Host "Expected failure occurred: $($_.Exception.Response.StatusCode)"
}

# Delete entry with writer token
Write-Host "`n6. Deleting entry with writer token..."
$headers = @{ "Authorization" = "Bearer $writerToken" }
$response = Invoke-RestMethod -Method Put -Uri "$BASE_URL/PhoneBook/deleteByName?name=Bruce%20Schneier" -Headers $headers
Write-Host "Response: $($response | ConvertTo-Json)"

# Try invalid inputs
Write-Host "`n7. Testing invalid inputs..."
$headers = @{
    "Authorization" = "Bearer $writerToken"
    "Content-Type" = "application/json"
}

# Test invalid name
$body = @{
    name = "L33t Hacker"
    phoneNumber = "(703)111-2121"
} | ConvertTo-Json
try {
    $response = Invoke-RestMethod -Method Post -Uri "$BASE_URL/PhoneBook/add" -Headers $headers -Body $body
} catch {
    Write-Host "Invalid name test - Expected failure occurred: $($_.Exception.Response.StatusCode)"
}

# Test invalid phone
$body = @{
    name = "Valid Name"
    phoneNumber = "invalid-phone"
} | ConvertTo-Json
try {
    $response = Invoke-RestMethod -Method Post -Uri "$BASE_URL/PhoneBook/add" -Headers $headers -Body $body
} catch {
    Write-Host "Invalid phone test - Expected failure occurred: $($_.Exception.Response.StatusCode)"
}

Write-Host "`nAll tests completed!" 