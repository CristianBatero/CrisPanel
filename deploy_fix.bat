@echo off
echo === Desplegando CrisPanel ===
echo 1. Agregando cambios...
git add .
echo.

echo 2. Confirmando cambios...
set /p msg="Escribe el mensaje del commit (Enter para default): "
if "%msg%"=="" set msg="Update CrisPanel with Stability Fixes"
git commit -m "%msg%"
echo.

echo 3. Subiendo al repositorio (GitHub)...
git push origin main
echo.

echo === Despliegue completado ===
echo Si tienes un servicio conectado (como Netlify/Vercel/Render), el despliegue deberia iniciar automaticamente.
pause
