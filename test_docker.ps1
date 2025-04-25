# Test script for Phone Book API in Docker
param (
    [string]$apiUrl = "http://localhost:8000"  # Default URL for local development
)

Write-Host "Starting Comprehensive Docker API Tests..." -ForegroundColor Green
Write-Host "Using API URL: $apiUrl" -ForegroundColor Yellow

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
            return $true
        } else {
            Write-Host "Test Failed! Expected status $expectedStatus, got $($response.StatusCode)" -ForegroundColor Red
            return $false
        }
        
    } catch {
        if ($_.Exception.Response) {
            $statusCode = $_.Exception.Response.StatusCode.value__
            $reader = [System.IO.StreamReader]::new($_.Exception.Response.GetResponseStream())
            $errorBody = $reader.ReadToEnd()
            $reader.Close()
            
            Write-Host "Response: $errorBody"
            
            if ($statusCode -eq $expectedStatus) {
                Write-Host "Test Passed!" -ForegroundColor Green
                return $true
            } else {
                Write-Host "Test Failed! Expected status $expectedStatus, got $statusCode" -ForegroundColor Red
                return $false
            }
        } else {
            Write-Host "Error: $($_.Exception.Message)" -ForegroundColor Red
            return $false
        }
    }
}

# Wait for container to be healthy
Write-Host "`nWaiting for container to be healthy..." -ForegroundColor Yellow
$maxAttempts = 30
$attempt = 0
$healthy = $false

while ($attempt -lt $maxAttempts -and -not $healthy) {
    $attempt++
    Write-Host ("Attempt {0} of {1}: Checking container health..." -f $attempt, $maxAttempts)
    
    try {
        $response = Invoke-WebRequest -Uri "$apiUrl/docs" -Method Get -ErrorAction Stop
        if ($response.StatusCode -eq 200) {
            $healthy = $true
            Write-Host "Container is healthy!" -ForegroundColor Green
        }
    } catch {
        Write-Host "Container not ready yet, waiting..."
        Start-Sleep -Seconds 2
    }
}

if (-not $healthy) {
    Write-Host "Container failed to become healthy after $maxAttempts attempts" -ForegroundColor Red
    exit 1
}

# Get authentication tokens
Write-Host "`nGetting authentication tokens..." -ForegroundColor Yellow

try {
    # Reader token
    $readerCredentials = @{
        username = "reader"
        password = "readerpass"
    }
    $readerResponse = Invoke-WebRequest -Uri "$apiUrl/token" -Method Post -Body $readerCredentials -ErrorAction Stop
    $readerToken = ($readerResponse.Content | ConvertFrom-Json).access_token
    Write-Host "Reader token acquired successfully" -ForegroundColor Green

    # Writer token
    $writerCredentials = @{
        username = "writer"
        password = "writerpass"
    }
    $writerResponse = Invoke-WebRequest -Uri "$apiUrl/token" -Method Post -Body $writerCredentials -ErrorAction Stop
    $writerToken = ($writerResponse.Content | ConvertFrom-Json).access_token
    Write-Host "Writer token acquired successfully" -ForegroundColor Green
} catch {
    Write-Host "Error getting authentication tokens: $($_.Exception.Message)" -ForegroundColor Red
    if ($_.Exception.Response) {
        $reader = [System.IO.StreamReader]::new($_.Exception.Response.GetResponseStream())
        $errorBody = $reader.ReadToEnd()
        $reader.Close()
        Write-Host "Response: $errorBody" -ForegroundColor Red
    }
    exit 1
}

# Initialize test results
$testResults = @()
$totalTests = 0
$passedTests = 0

# Test 1: Authentication Tests
$totalTests++
$result = Invoke-ApiTest -testName "Invalid Login" -method "POST" -endpoint "/token" -body @{username="invalid";password="invalid"} -expectedStatus 401
$testResults += @{Name="Invalid Login"; Passed=$result}
if ($result) { $passedTests++ }

# Test 2: List Entries (Read Permission)
$totalTests++
$result = Invoke-ApiTest -testName "List Entries (Reader)" -method "GET" -endpoint "/PhoneBook/list" -token $readerToken -expectedStatus 200
$testResults += @{Name="List Entries (Reader)"; Passed=$result}
if ($result) { $passedTests++ }

# Test 3: Add Valid Entry
$totalTests++
$validEntry = @{
    name = "Bruce Schneier"
    phone_number = "(703)111-2121"
}
$result = Invoke-ApiTest -testName "Add Valid Entry" -method "POST" -endpoint "/PhoneBook/add" -body $validEntry -token $writerToken -expectedStatus 200
$testResults += @{Name="Add Valid Entry"; Passed=$result}
if ($result) { $passedTests++ }

# Test 4: Add Invalid Entry (Invalid Name)
$totalTests++
$invalidEntry = @{
    name = "L33t Hacker"
    phone_number = "(703)111-2121"
}
$result = Invoke-ApiTest -testName "Add Invalid Entry (Invalid Name)" -method "POST" -endpoint "/PhoneBook/add" -body $invalidEntry -token $writerToken -expectedStatus 422
$testResults += @{Name="Add Invalid Entry (Invalid Name)"; Passed=$result}
if ($result) { $passedTests++ }

# Test 5: Add Invalid Entry (Invalid Phone)
$totalTests++
$invalidEntry = @{
    name = "Bruce Schneier"
    phone_number = "123"
}
$result = Invoke-ApiTest -testName "Add Invalid Entry (Invalid Phone)" -method "POST" -endpoint "/PhoneBook/add" -body $invalidEntry -token $writerToken -expectedStatus 422
$testResults += @{Name="Add Invalid Entry (Invalid Phone)"; Passed=$result}
if ($result) { $passedTests++ }

# Test 6: Add Entry with Reader Token (Should Fail)
$totalTests++
$result = Invoke-ApiTest -testName "Add Entry with Reader Token" -method "POST" -endpoint "/PhoneBook/add" -body $validEntry -token $readerToken -expectedStatus 403
$testResults += @{Name="Add Entry with Reader Token"; Passed=$result}
if ($result) { $passedTests++ }

# Test 7: Delete by Name
$totalTests++
$result = Invoke-ApiTest -testName "Delete by Name" -method "PUT" -endpoint "/PhoneBook/deleteByName?name=Bruce%20Schneier" -token $writerToken -expectedStatus 200
$testResults += @{Name="Delete by Name"; Passed=$result}
if ($result) { $passedTests++ }

# Test 8: Delete Non-existent Entry
$totalTests++
$result = Invoke-ApiTest -testName "Delete Non-existent Entry" -method "PUT" -endpoint "/PhoneBook/deleteByName?name=NonExistent" -token $writerToken -expectedStatus 404
$testResults += @{Name="Delete Non-existent Entry"; Passed=$result}
if ($result) { $passedTests++ }

# Test 9: Add Multiple Valid Entries
$validEntries = @(
    @{ name = "Schneier, Bruce"; phone_number = "123-4567" },
    @{ name = "O'Malley, John F."; phone_number = "+1(703)111-2121" },
    @{ name = "Cher"; phone_number = "12345" }
)

foreach ($entry in $validEntries) {
    $totalTests++
    $result = Invoke-ApiTest -testName "Add Valid Entry ($($entry.name))" -method "POST" -endpoint "/PhoneBook/add" -body $entry -token $writerToken -expectedStatus 200
    $testResults += @{Name="Add Valid Entry ($($entry.name))"; Passed=$result}
    if ($result) { $passedTests++ }
}

# Test 10: Test Invalid Phone Numbers
$invalidPhones = @(
    @{ name = "Test User"; phone_number = "123" },
    @{ name = "Test User"; phone_number = "1/703/123/1234" },
    @{ name = "Test User"; phone_number = "<script>alert('XSS')</script>" }
)

foreach ($entry in $invalidPhones) {
    $totalTests++
    $result = Invoke-ApiTest -testName "Add Entry with Invalid Phone ($($entry.phone_number))" -method "POST" -endpoint "/PhoneBook/add" -body $entry -token $writerToken -expectedStatus 422
    $testResults += @{Name="Add Entry with Invalid Phone ($($entry.phone_number))"; Passed=$result}
    if ($result) { $passedTests++ }
}

# Test 11: Delete by Phone Number
$totalTests++
$result = Invoke-ApiTest -testName "Delete by Phone Number" -method "PUT" -endpoint "/PhoneBook/deleteByNumber?phone_number=123-4567" -token $writerToken -expectedStatus 200
$testResults += @{Name="Delete by Phone Number"; Passed=$result}
if ($result) { $passedTests++ }

# Test 12: List Entries After Operations
$totalTests++
$result = Invoke-ApiTest -testName "List Entries After Operations" -method "GET" -endpoint "/PhoneBook/list" -token $readerToken -expectedStatus 200
$testResults += @{Name="List Entries After Operations"; Passed=$result}
if ($result) { $passedTests++ }

# Test 13: Test SQL Injection Attempt
$totalTests++
$sqlInjectionEntry = @{
    name = "'; DROP TABLE phonebook; --"
    phone_number = "(703)111-2121"
}
$result = Invoke-ApiTest -testName "SQL Injection Attempt" -method "POST" -endpoint "/PhoneBook/add" -body $sqlInjectionEntry -token $writerToken -expectedStatus 422
$testResults += @{Name="SQL Injection Attempt"; Passed=$result}
if ($result) { $passedTests++ }

# Test 14: Test XSS Attempt
$totalTests++
$xssEntry = @{
    name = "<script>alert('XSS')</script>"
    phone_number = "(703)111-2121"
}
$result = Invoke-ApiTest -testName "XSS Attempt" -method "POST" -endpoint "/PhoneBook/add" -body $xssEntry -token $writerToken -expectedStatus 422
$testResults += @{Name="XSS Attempt"; Passed=$result}
if ($result) { $passedTests++ }

# Display test results summary
Write-Host "`nTest Results Summary:" -ForegroundColor Cyan
Write-Host "Total Tests: $totalTests"
Write-Host "Passed Tests: $passedTests"
Write-Host "Failed Tests: $($totalTests - $passedTests)"

Write-Host "`nDetailed Results:" -ForegroundColor Cyan
foreach ($test in $testResults) {
    $status = if ($test.Passed) { "PASSED" } else { "FAILED" }
    $color = if ($test.Passed) { "Green" } else { "Red" }
    Write-Host "$($test.Name): $status" -ForegroundColor $color
}

# Exit with error code if any tests failed
if ($passedTests -lt $totalTests) {
    Write-Host "`nSome tests failed. Exiting with error code 1." -ForegroundColor Red
    exit 1
} else {
    Write-Host "`nAll tests passed successfully!" -ForegroundColor Green
    exit 0
}