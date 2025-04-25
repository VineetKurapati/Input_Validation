# Test script for Phone Book API
param (
    [string]$apiUrl = "http://localhost:8000"  # Default URL for local development
)

Write-Host "Starting API Tests..." -ForegroundColor Green
Write-Host "Using API URL: $apiUrl" -ForegroundColor Yellow

# Test API connection first
Write-Host "`nTesting API connection..." -ForegroundColor Yellow
try {
    $response = Invoke-WebRequest -Uri "$apiUrl/docs" -Method Get -ErrorAction Stop
    Write-Host "API connection successful! Swagger UI detected." -ForegroundColor Green
} catch {
    Write-Host "Failed to connect to API: $_" -ForegroundColor Red
    exit 1
}

# Function to make API calls and display results
function Invoke-ApiTest {
    param (
        [string]$testName,
        [string]$method,
        [string]$endpoint,
        [object]$body = $null,
        [string]$token = "",
        [int]$expectedStatus = 200
    )
    
    Write-Host "`nTesting: $testName" -ForegroundColor Cyan
    
    try {
        $headers = @{
            'Content-Type' = if ($endpoint -eq "/token") { 'application/x-www-form-urlencoded' } else { 'application/json' }
        }
        
        if ($token) {
            $headers['Authorization'] = "Bearer $token"
        }
        
        $params = @{
            Uri = "$apiUrl$endpoint"
            Method = $method
            Headers = $headers
            ErrorAction = 'Stop'
        }
        
        if ($null -ne $body) {
            if ($endpoint -eq "/token") {
                $params['Body'] = $body
            } else {
                $params['Body'] = $body | ConvertTo-Json -Compress
                $params['ContentType'] = 'application/json'
            }
        }
        
        $response = Invoke-WebRequest @params
        Write-Host "Response: $($response.Content)"
        Write-Host "Status: $($response.StatusCode)"
        
        if ($response.StatusCode -eq $expectedStatus) {
            Write-Host "Test Passed!" -ForegroundColor Green
        } else {
            Write-Host "Test Failed! Expected status $expectedStatus, got $($response.StatusCode)" -ForegroundColor Red
        }
        
    } catch {
        $statusCode = $_.Exception.Response.StatusCode.value__
        $reader = [System.IO.StreamReader]::new($_.Exception.Response.GetResponseStream())
        $errorBody = $reader.ReadToEnd()
        $reader.Close()
        
        Write-Host "Response: $errorBody"
        
        if ($statusCode -eq $expectedStatus) {
            Write-Host "Test Passed!" -ForegroundColor Green
        } else {
            Write-Host "Test Failed! Expected status $expectedStatus, got $statusCode" -ForegroundColor Red
        }
    }
}

# Get authentication tokens
Write-Host "`nGetting authentication tokens..." -ForegroundColor Yellow

try {
    # Reader token
    $readerCredentials = @{
        username = "reader"
        password = "readerpass"
        grant_type = "password"
    }
    $readerResponse = Invoke-WebRequest -Uri "$apiUrl/token" -Method Post -Body $readerCredentials -ContentType "application/x-www-form-urlencoded" -ErrorAction Stop
    $readerToken = ($readerResponse.Content | ConvertFrom-Json).access_token
    Write-Host "Reader token acquired successfully" -ForegroundColor Green

    # Writer token
    $writerCredentials = @{
        username = "writer"
        password = "writerpass"
        grant_type = "password"
    }
    $writerResponse = Invoke-WebRequest -Uri "$apiUrl/token" -Method Post -Body $writerCredentials -ContentType "application/x-www-form-urlencoded" -ErrorAction Stop
    $writerToken = ($writerResponse.Content | ConvertFrom-Json).access_token
    Write-Host "Writer token acquired successfully" -ForegroundColor Green
} catch {
    if ($_.Exception.Response) {
        $reader = [System.IO.StreamReader]::new($_.Exception.Response.GetResponseStream())
        $errorBody = $reader.ReadToEnd()
        $reader.Close()
        Write-Host "Failed to get authentication tokens: $errorBody" -ForegroundColor Red
    } else {
        Write-Host "Failed to get authentication tokens: $($_.Exception.Message)" -ForegroundColor Red
    }
    exit 1
}

# Test 1: Authentication Tests
$invalidCredentials = @{
    username = "invalid"
    password = "invalid"
}
Invoke-ApiTest -testName "Invalid Login" -method "POST" -endpoint "/token" -body $invalidCredentials -expectedStatus 401

# Test 2: List Entries (Read Permission)
Invoke-ApiTest -testName "List Entries (Reader)" -method "GET" -endpoint "/PhoneBook/list" -token $readerToken -expectedStatus 200

# Test 3: Add Entry (Write Permission)
$validEntry = @{
    name = "Bruce Schneier"
    phone_number = "(703)111-2121"
}
Invoke-ApiTest -testName "Add Valid Entry" -method "POST" -endpoint "/PhoneBook/add" -body $validEntry -token $writerToken -expectedStatus 200

# Test 4: Add Invalid Entry
$invalidEntry = @{
    name = "L33t Hacker"
    phone_number = "123"
}
Invoke-ApiTest -testName "Add Invalid Entry" -method "POST" -endpoint "/PhoneBook/add" -body $invalidEntry -token $writerToken -expectedStatus 422

# Test 5: Add Entry with Reader Token (Should Fail)
Invoke-ApiTest -testName "Add Entry with Reader Token" -method "POST" -endpoint "/PhoneBook/add" -body $validEntry -token $readerToken -expectedStatus 403

# Test 6: Delete by Name
Invoke-ApiTest -testName "Delete by Name" -method "PUT" -endpoint "/PhoneBook/deleteByName?name=Bruce%20Schneier" -token $writerToken -expectedStatus 200

# Test 7: Delete Non-existent Entry
Invoke-ApiTest -testName "Delete Non-existent Entry" -method "PUT" -endpoint "/PhoneBook/deleteByName?name=NonExistent" -token $writerToken -expectedStatus 404

# Test 8: Add Multiple Valid Entries
$validEntries = @(
    @{ name = "Schneier, Bruce"; phone_number = "123-4567" },
    @{ name = "O'Malley, John F."; phone_number = "+1(703)111-2121" },
    @{ name = "Cher"; phone_number = "12345" }
)

foreach ($entry in $validEntries) {
    Invoke-ApiTest -testName "Add Valid Entry" -method "POST" -endpoint "/PhoneBook/add" -body $entry -token $writerToken -expectedStatus 200
}

# Test 9: Test Invalid Phone Numbers
$invalidPhones = @(
    @{ name = "Test User"; phone_number = "123" },
    @{ name = "Test User"; phone_number = "1/703/123/1234" },
    @{ name = "Test User"; phone_number = "<script>alert('XSS')</script>" }
)

foreach ($entry in $invalidPhones) {
    Invoke-ApiTest -testName "Add Entry with Invalid Phone" -method "POST" -endpoint "/PhoneBook/add" -body $entry -token $writerToken -expectedStatus 422
}

# Test 10: Delete by Phone Number
Invoke-ApiTest -testName "Delete by Phone Number" -method "PUT" -endpoint "/PhoneBook/deleteByNumber?phone_number=123-4567" -token $writerToken -expectedStatus 200

Write-Host "`nAll tests completed!" -ForegroundColor Green 