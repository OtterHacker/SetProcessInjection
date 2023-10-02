# SetProcessInjection
This is a POC from my article on the subject : https://www.riskinsight-wavestone.com/en/2023/10/process-injection-using-ntsetinformationprocess/

Please, do not compile and run it as is or I will get a nice Cobalt callback on my C2. If you saw several `calc.exe` spawning on your machine, that must be me...

To use it, first encrypt your beacon using the `payload/encryptor.py` script, it will create a [sc.h](https://youtu.be/-CVn3-3g_BI?t=23) file in your project directory, then compile the project and enjoy.
