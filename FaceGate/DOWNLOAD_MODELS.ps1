$ErrorActionPreference = 'Stop'
Set-Location -LiteralPath $PSScriptRoot
$modelsDirectory = Join-Path $PSScriptRoot 'models'
New-Item -ItemType Directory -Path $modelsDirectory -Force | Out-Null

$models = @(
    @{
        Name = 'YuNet face detection'
        FileName = 'face_detection_yunet_2023mar.onnx'
        Url = 'https://huggingface.co/opencv/opencv_zoo/resolve/main/models/face_detection_yunet/face_detection_yunet_2023mar.onnx'
        Sha256 = '8f2383e4dd3cfbb4553ea8718107fc0423210dc964f9f4280604804ed2552fa4'
    },
    @{
        Name = 'SFace face recognition'
        FileName = 'face_recognition_sface_2021dec.onnx'
        Url = 'https://huggingface.co/opencv/opencv_zoo/resolve/main/models/face_recognition_sface/face_recognition_sface_2021dec.onnx'
        Sha256 = '0ba9fbfa01b5270c96627c4ef784da859931e02f04419c829e83484087c34e79'
    }
)

foreach ($model in $models) {
    $destination = Join-Path $modelsDirectory $model.FileName
    $partial = "$destination.download"
    Write-Host "`nDownloading $($model.Name)..." -ForegroundColor Cyan
    try {
        if (Test-Path -LiteralPath $partial) {
            Remove-Item -LiteralPath $partial -Force
        }
        Invoke-WebRequest -Uri $model.Url -OutFile $partial -UseBasicParsing
        if (!(Test-Path -LiteralPath $partial) -or (Get-Item -LiteralPath $partial).Length -lt 10000) {
            throw 'Downloaded file is missing or unexpectedly small.'
        }
        $actualHash = (Get-FileHash -LiteralPath $partial -Algorithm SHA256).Hash.ToLowerInvariant()
        if ($actualHash -ne $model.Sha256) {
            throw "SHA256 mismatch. Expected $($model.Sha256); got $actualHash."
        }
        Move-Item -LiteralPath $partial -Destination $destination -Force
        Write-Host "Verified: $($model.FileName)" -ForegroundColor Green
    }
    catch {
        if (Test-Path -LiteralPath $partial) {
            Remove-Item -LiteralPath $partial -Force -ErrorAction SilentlyContinue
        }
        Write-Error "Failed for $($model.FileName): $($_.Exception.Message)"
        exit 1
    }
}

Write-Host "`nAll models downloaded and verified." -ForegroundColor Green
exit 0
