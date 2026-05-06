 takeown /f "C:\srv\ftp\pass.csv"; icacls "C:\srv\ftp\pass.csv" /grant "$env:USERNAME:F"; Remove-Item "C:\srv\ftp\pass.csv" -Force
