**Senario 1: Web site defacement**

**\#101: What is the likely IPv4 address of someone from the Po1s0n1vy
group scanning imreallynotbatman.com for web application
vulnerabilities?**

Đầu tiên ta sẽ query xem có các loại index và sourcetype nào:

![](media/image1.png){width="4.461525590551181in"
height="2.0057797462817146in"}

![](media/image2.png){width="4.404623797025372in"
height="5.057975721784777in"}

Theo kết quả, ta có sourcetype stream:http, suricata, fgt\_utm, iis và
index có botsv1.

Thử kiểm tra theo sourcetype stream:http xem chúng ta có được thông tin
gì ?

![](media/image3.png){width="4.167630139982502in"
height="5.073288495188102in"}

Ta thấy được có 2 IP liên quan tới URL imreallynotbatman.com.

Đề bài yêu cầu tìm Ipv4 scan trang web imreallynotbatman.com vì vậy cách
tốt nhất là kiểm tra URL.

![](media/image4.png){width="4.15in" height="3.7412062554680663in"}

![](media/image5.png){width="4.150288713910761in"
height="1.8114140419947506in"}

Sau khi kiểm tra, ta thấy URL của 2 IP là khác nhau. IP 23.22.63.114 chỉ
tương tác với URL trang administrator của joomla còn IP 40.80.148.42 thì
tương tác với nhiều URL lạ và có thể thấy đây là hành vi scan URL.

Vì vậy đáp án là **40.80.148.42**.

Đáp án có thể đến với nhiều cách khác nhau, ta có thể dành thời gian để
đọc stream:http và ta sẽ thấy được vài thứ hay ho! xD.

![](media/image6.png){width="6.5in" height="2.904166666666667in"}

Đây rồi! :D Acunetix Web Vulnerability Scanner đi cùng với source IP
40.80.148.42. =&gt; Đáp án cho IP Scan mà đề bài yêu cầu là
40.80.148.42.

**\#102: What company created the web vulnerability scanner used by
Po1s0n1vy? Type the company name.**

Như đã nói ở trên, câu này ta chỉ cần đọc stream:http một lúc là ra.

Đáp án là: **Acunetix**.

Acunetix hay Acunetix Web Vulnerability Scanner (Acunetix WVS) là một
công cụ scan lỗ hổng ứng dụng web được cung bởi công ty cùng tên vào năm
2005.

![](media/image6.png){width="7.089677384076991in"
height="3.167630139982502in"}

**\#103: What content management system is imreallynotbatman.com likely
using?**

Trước khi làm câu này, ta cần search google 1 chút nếu như chưa biết đến
khái niệm content management system (CMS).

Lên google search what is content management system.

![](media/image7.png){width="4.653179133858267in"
height="3.535621172353456in"}

Ngay lập tức google sẽ hiển thị ra những loại phần mềm được sử dụng
trong CMS và trong đó có joomla, một công cụ CMS được sử dụng bởi trang
web imreallynotbatman.com trong boss of soc v1. Như đã nói, đọc
stream:http một lúc là tìm ra ngay xD.

Đáp án là **joomla**

![](media/image8.png){width="5.433525809273841in"
height="4.028123359580053in"}

Ta có thể vào link đầu tiên hoặc bất cứ trang nào mà bạn tìm được để đọc
khái niệm về CMS. Về cơ bản, CMS đúng như tên gọi, nó là hệ quản trị nội
dung của trang web, có chức năng điều khiển tất cả hoạt động về nội
dung, thông tin của website.

![](media/image9.png){width="4.410404636920385in"
height="3.82706583552056in"}

**\#104:** **What is the name of the file that defaced the
imreallynotbatman.com website? Please submit only the name of the file
with extension?**

Câu này hơi rối rắm và mất thời gian một chút. Đề bài yêu cầu tìm tên
của file mà đã deface trang web imreallynotbatman.com. Bạn sẽ nghĩ tới
điều gì đầu tiên khi nhắc đến một file đã deface web của nạn nhân? Chắc
hẳn ta đều nghĩ rằng file đó sẽ xuất hiện trong URI mà attacker truy cập
và bằng một cách nào đó, attacker có thể “tuồn” được file đó vào máy nạn
nhận thông ra URL. Mình cũng từng nghĩ như vậy xD. Sau đó mình đặt
source ip là IP của attacker và dành khá nhiều thời gian tìm đi tìm lại
trong đám URL nhưng vẫn còn quá nhiều kết quả. Vốn dĩ không có kết quả
là vì hướng làm của câu này không phải như vậy.

Hãy thử nghĩ xem, để “tuồn” được một file vào máy nạn nhân thì có những
cách nào? Hmm, upload file qua URL ư… có thể lắm chứ… nhưng cách đó
không hiệu quả rồi :P. Nếu như nạn nhân tải một file từ một nguồn nào đó
trên internet về thì sao? (Attacker có thể upload file lên internet và
cài cắm mã độc vào máy nạn nhân thực thi lệnh download file). Hmm, có
thể lắm chứ. Thử kiểm tra nhé xD.

Xác định được IP đích mà attacker tương tác đến.

![](media/image10.png){width="5.011560586176728in"
height="2.352648731408574in"}

Có 2 IP, trong đó IP 192.168.250.70 có lượng tương tác cao. Có vẻ đây
chính là IP của nạn nhân mà chúng ta đang cần tìm. Thử để source IP là
IP này xem nó tương tác thế nào :D.

![](media/image11.png){width="5.109826115485564in"
height="2.6930325896762906in"}

Hmm, 8 event à…. Kiểm tra URL mà IP này tương tác coi sao.

![](media/image12.png){width="5.277456255468066in"
height="3.3812937445319333in"}

À! nó đây rồi xD. Đáp án là **poisonivy-is-coming-for-you-batman.jpeg**

**\#105:** **This attack used dynamic DNS to resolve to the malicious
IP. What fully qualified domain name (FQDN) is associated with this
attack?**

Câu này bảo rằng cuộc tấn công này sử dụng dynamic DNS (DNS động) để
tránh việc bị detect malicious IP và yêu cầu tìm fully qualified domain
name (tên miền đầy đủ) liên quan đến cuộc tấn công.

Trước khi làm thì chúng ta sẽ cùng tìm hiểu một chút về dynamic DNS và
fully qualified domain name nhé.

Dynamic DNS là cơ chế sẽ giúp ánh xạ tên miền đến địa chỉ IP động.

Fully qualified domain name hay tên miền đầy đủ là một tên miền tuyệt
đối, vì nó cung cấp đường dẫn tuyệt đối và đầy đủ nhất của host. Ví dụ
mail server trên domain example.com có ​​thể có FQDN là
mail.example.com.

Từ kết quả của câu 104, ta thấy file deface web được down về từ tên miền
như hình bên dưới.

![](media/image13.png){width="6.5in" height="4.038194444444445in"}

Yeb :3 đáp án là **prankglassinebracket.jumpingcrab.com**

**\#106: What IPv4 address has Po1s0n1vy tied to domains that are
pre-staged to attack Wayne Enterprises?**

Câu này yêu cầu tìm IP được sử dụng để liên kết với các domain được dàn
dựng cho cuộc tấn công. Hmm, thử tìm tất cả source IP và destination IP
liên quan đến URL chứa tên miền xem sao.

![](media/image14.png){width="6.5in" height="2.097916666666667in"}

Hmm, chỉ có thằng destition IP Public này thôi. Thử coi event của nó coi
sao.

![](media/image15.png){width="4.017341426071741in"
height="3.9626301399825024in"}

Ầu :3 nó là IP được gán cho tên miền
prankglassinebracket.jumpingcrab.com là đáp án của câu 105. Well, thế mà
mình cứ tìm vòng vo mãi :v đáp án có ngay ở event chứa đáp án của câu
trên.\
Đáp án là **23.22.63.114**

**\#107: Based on the data gathered from this attack and common open
source intelligence sources for domain names, what is the email address
that is most likely associated with Po1s0n1vy APT group?**

Câu này yêu cầu tìm email của nhóm Po1s0n1vy. Do không đọc kĩ đề bài nên
mình mất khá nhiều thời gian. Lưu ý để tìm đáp án cho câu này thì không
search trên hệ thống splunk được… đừng mất thời gian. Chú ý đoạn “open
source intelligence” của đề bài nhé bạn phải sử dụng kỹ năng threat
intelligence để giải.

Sử dụng AlienVault để kiểm tra thông tin về IP tìm được ở câu 106
<https://otx.alienvault.com>.

![](media/image16.png){width="6.5in" height="3.342361111111111in"}

Ta thấy xuất hiện 1 hostname có tên là po1s0n1vy.com rất đáng ngờ. Kiểm
tra hostname này với alienvault xem sao.

![](media/image17.png){width="6.5in" height="3.092361111111111in"}

Phần whois cho ta biết thông tin về email được sử dụng. Hmm, trang 1 có
vẻ không có gì đặc biệt cho lắm…. kiểm tra trang 2 xem sao.

![](media/image18.png){width="6.5in" height="2.7118055555555554in"}

Đây rồi :D, đã là email có tên miền là po1s0n1vy.com thì không lệch đi
đâu được.

Đáp án là **lillian.rose@po1s0n1vy.com**

Kinh nghiệm xương máu…… đọc kỹ đề bài .

**\#108: What IPv4 address is likely attempting a brute force password
attack against imreallynotbatman.com?**

Câu này yêu cầu ta tìm IP bruteforce vào tên miền imreallynotbatman.com.
Các cuộc tấn công bruteforce thường dùng giao thức POST của http. Ta sẽ
kiểm tra trường form\_data để xem form dữ liệu được provide lên server.
Sử dụng câu query đơn giản như hình bên dưới.

![](media/image19.png){width="6.3386318897637794in"
height="3.7916666666666665in"}

Như ta thấy, IP 23.22.63.114 là IP bruteforce.

Đáp án là **23.22.63.114**

**\#109: What is the name of the executable uploaded by Po1s0n1vy?**

Câu này yêu cầu tìm file exe đã được upload thành công. Sử dụng câu
query bên dưới để tìm các file exe.

![](media/image20.png){width="6.5in" height="4.603472222222222in"}

Hmm, có 16 event tất cả. Vậy làm sao để tìm được file exe ta muốn trong
đống 16 event này?

Hãy thử đặt câu hỏi là “Khi một file được upload thành công lên server
thì server sẽ phản hồi như thế nào?” Thử kiểm tra với trường
dest\_content để xem các phản hồi từ IP đích nhé.

![](media/image21.png){width="5.298611111111111in"
height="3.107273622047244in"}

![](media/image22.png){width="6.5in" height="3.026388888888889in"}

Có gì dó hay ho nè :D message: Upload successful!. Thử kiểm tra event
này xem sao.

![](media/image23.png){width="6.5in" height="2.970833333333333in"}

Ra rồi nè. Đáp án là **3791.exe**

**\#110: What is the MD5 hash of the executable uploaded?**

Câu này yêu cầu tìm mã MD5 hash của file đã được upload mà ta tìm được
từ câu 109. Để tìm được mã MD5 thì phải tìm trong log sysmon. Thử query
xem ta tìm được gì nào.

![](media/image24.png){width="6.5in" height="2.323611111111111in"}

Yes, có mã MD5 nhưng 69 event :D. Thử nghĩ xem, khi một file exe được
upload và thực thi thành công trên server thì chắc chắn phải tạo ra một
process của riêng nó. Vậy từ suy luận này, làm cách nào để ta tìm được
mã MD5 mà ta mong muốn.

Ở bên trái, có một trường sẽ show cho chúng ta các image đã được khởi
chạy có tên là Image. Bên trong trường này có một giá trị là
C:\\inetpub\\wwwroot\\joomla\\3791.exe (Xem hình bên dưới).

![](media/image25.png){width="6.5in" height="2.582638888888889in"}

Kiểm tra với giá trị của trường Image thì vẫn có đến 64 event.

![](media/image26.png){width="6.5in" height="2.4583333333333335in"}

Tiếp tục kiểm tra theo suy luận đã nêu ở bên trên. Ta bắt gặp trường
signature có 1 giá trị là Process Create và chỉ có 1 event.

![](media/image27.png){width="6.0in" height="2.8692300962379704in"}

Kiểm tra 1 event đó và ta có được đáp án cho câu này.

![](media/image28.png){width="6.5in" height="1.9930555555555556in"}

Đáp án là **AAE3F5A29935E6ABCC2C2754D12A9AF0**

**\#111: GCPD reported that common TTPs (Tactics, Techniques,
Procedures) for the Po1s0n1vy APT group, if initial compromise fails, is
to send a spear phishing email with custom malware attached to their
intended target. This malware is usually connected to Po1s0n1vys initial
attack infrastructure. Using research techniques, provide the SHA256
hash of this malware.**

Câu này yêu cầu tìm mã SHA256 của một file malware được đính kèm trong
một phishing email. Được biết malware này thường xuyên connect tới hạ
tầng tấn công ban đầu của nhóm Po1s0n1vys.

Câu này tiếp tục không thể search trên hệ thống splunk mà phải dùng đến
kỹ năng threat intelligence. Cơ sở hạ tầng tấn công ban đầu của nhóm
Po1s0n1vys là IP 23.22.63.114. Lúc đầu mình tưởng IP 40.80.148.42 là cơ
sở hạ tầng tấn công ban đầu nhưng không phải, 23.22.63.114 là IP chủ
động tấn công Bruteforce vào vào máy nạn nhân và nạn nhân cũng đã từng
download 1 file mà đã deface web từ IP này.

Kiểm tra IP trên VirusTotal ta tìm được IP này có giao tiếp với 3 file
có chứa mã độc.

![](media/image29.png){width="6.5in" height="4.721527777777778in"}

Tiếp tục tiến hành kiểm tra 3 file này. Theo đề bài thì malware thường
xuyên giao tiếp với cơ sở hạ tầng tấn công ban đầu có nghĩa là malware
chỉ giao tiếp đơn thuần với IP 23.22.63.114 mà thôi. Để hiểu rõ hơn thì
chúng ta sẽ đi vào phân tích 3 malware ngay sau đây.

File **check.exe:** File này có giao tiếp với IP 23.22.63.114, nhưng lại
là qua HTTP request nên ta bỏ qua trường hợp này. Vì sao ư? Vì IP cơ sở
hạ tầng tấn công ban đầu của nhóm hacker là IP 23.22.63.114 mà không đi
kèm giao thức HTTP hay DNS request.

![](media/image30.png){width="6.5in" height="4.188888888888889in"}

![](media/image31.png){width="5.590277777777778in"
height="4.343813429571304in"}

¯\\\_(ツ)\_/¯

File **ab.exe:** Trường hợp này cũng bỏ qua luôn vì ở phần RELATIONS ta
có thể thấy malware này có contact đến IP 23.22.63.114, nhưng khi sang
phần BEHAVIOR để kiểm tra thì ta thấy malware này lại không có dấu hiệu
giữ phiên giao tiếp với IP 23.22.63.114 thuộc cơ sở hạ tầng tấn công ban
đầu của nhóm hacker.

![](media/image32.png){width="5.98036198600175in"
height="4.131944444444445in"}

![](media/image33.png){width="5.034722222222222in"
height="4.01378937007874in"}

File **MirandaTateScreensaver.scr.exe:** Tất nhiên khi 2 file kia sai
thì file còn lại là đúng rồi ( ͡° ͜ʖ ͡°). Nhưng để hiểu rõ hơn thì mình sẽ
phân tích xem như nào nhé.

Phần RELATIONS có xuất hiện Contacted IP 23.22.63.114 giống file ab.exe.

![](media/image34.png){width="6.05689523184602in"
height="4.993055555555555in"}

Khác với file ab.exe, khi ta kiểm tra BEHAVIOR thì tại phần Network
Communication có xuất hiện IP 23.22.63.114. Điều này có nghĩa là file
này có contact tới IP 23.22.63.114 và có giữ phiên giao tiếp.

![](media/image35.png){width="5.268952318460192in" height="4.5in"}

Kiểm tra DETAILS để lấy được mã SHA256 của file malware.

![](media/image36.png){width="4.875in" height="4.038016185476815in"}

Đáp án là
**9709473ab351387aab9e816eff3910b9f28a7a70202e250ed46dba8f820f34a8.**

**\#112: What special hex code is associated with the customized malware
discussed in question 111?**

Câu này yêu cầu tìm mã hex được liên kết với malware được nhắc tới tại
phần thảo luận. Từ kết quả của câu 111, chuyển qua COMMUNITY, kéo xuống
một lúc là thấy đáp án ngay.

![](media/image37.png){width="6.5in" height="4.626388888888889in"}

![](media/image38.png){width="6.5in" height="2.967361111111111in"}

Đáp án là **53 74 65 76 65 20 42 72 61 6e 74 27 73 20 42 65 61 72 64 20
69 73 20 61 20 70 6f 77 65 72 66 75 6c 20 74 68 69 6e 67 2e 20 46 69 6e
64 20 74 68 69 73 20 6d 65 73 73 61 67 65 20 61 6e 64 20 61 73 6b 20 68
69 6d 20 74 6f 20 62 75 79 20 79 6f 75 20 61 20 62 65 65 72 21 21 21**.

**\#113: One of Po1s0n1vy's staged domains has some disjointed "unique"
whois information. Concatenate the two codes together and submit as a
single answer.**

Câu này cho ta biết thông tin là một trong những tên miền của nhóm
Po1s0n1vy có một số thông tin whois độc nhất rời rạc. Nhiễm vụ của ta là
phải tìm 2 đoạn mã của thông tin whois độc nhất rời rạc đó và ghép nó
lại với nhau để ra được đáp án.

Tên miền của nhóm Po1s0n1vy thì có khá nhiều. Ta sẽ kiểm tra thông tin
whois của các tên miền trên IP 23.22.63.114.

![](media/image39.png){width="6.5in" height="2.7402777777777776in"}

Khi mất kha khá thời gian kiểm tra các tên miền thì có một tên miền là
waynecorinc.com có thông tin whois khá thú vị. Ta sẽ kiểm tra whois
history của tên miền này vì hiện tại tên miền waynecorinc.com vẫn chưa
có ai sở hữu nên check whois không ra. Hiểu đơn giản thì whois history
là lịch sử sở hữu của tên miền.

![](media/image40.png){width="6.01898731408574in"
height="4.469867672790901in"}

Truy cập website <https://www.whoxy.com/whois-history/> để kiểm tra
whois history.

![](media/image41.png){width="4.930379483814523in"
height="3.79207239720035in"}

Site để tra cứu whois history mở ra, ta nhập tên miền và thực hiện
lookup.

![](media/image42.png){width="3.7848097112860892in"
height="3.509844706911636in"}

Sau khi kết quả hiện ra, ta kéo xuống dưới tại phần
administrative\_contact có một số thông tin khá thú vị. Ta thấy,
full\_name là LILLIAN ROSE và ngay sau đó tại phần company\_name và
mailing\_address là hai đoạn mã hex. Theo như đề bài thì đây chính là 2
đoạn mã đề bài đã nhắc tới.

![](media/image43.png){width="5.392404855643044in"
height="4.353674540682415in"}

Đề bài yêu cầu nối hai đoạn mã với nhau và gửi dưới dạng một câu trả lời
duy nhất, vì vậy ta sẽ nối chúng vào để có được đáp án cuối cùng.

Đáp án là **31 73 74 32 66 69 6E 64 67 65 74 73 66 72 65 65 62 65 65 72
66 72 6F 6D 72 79 61 6E 66 69 6E 64 68 69 6D 74 6F 67 65 74**

**\#114: What was the first brute force password used?**

Câu này yêu cầu tìm password đầu tiên được sử dụng trong cuộc tấn công
bruteforce. Từ kết quả của câu 108, ta biết được IP bruteforce là
23.22.63.114. Giờ ta sẽ thống kê thời gian lẫn form data của event theo
source IP là 23.22.63.114.

![](media/image44.png){width="6.5in" height="1.4520833333333334in"}

Nhấn vào chữ timestamp ở đầu cột để sắp xếp event sớm nhất thuộc trường
timestamp lên đầu. Mốc thời gian sớm nhất đi cùng form data sớm nhất.
Trong form data ta lấy được mật khẩu sớm nhất được sử dụng.

![](media/image45.png){width="6.5in" height="2.34375in"}

Mật khẩu đầu tiên được sử dụng là 12345678. Đáp án là **12345678.**

**\#115: One of the passwords in the brute force attack is James
Brodsky's favorite Coldplay song. We are looking for a six character
word on this one. Which is it?**

Câu này yêu cầu tìm một mật khẩu có 6 ký tự trong cuộc tấn công
bruteforce, được biết mật khẩu này là bài hát Coldplay yêu thích của
James Brodsky.

Vấn đề của câu này là làm sao để lọc được những mật khẩu có 6 ký tự. Để
làm được điều đó thì ta cần sử dụng lệnh **rex** trong câu query. Tham
khảo câu query ở hình bên dưới.

![](media/image46.png){width="6.5in" height="2.1180555555555554in"}

Giải thích một chút nhé! Phần query phía trên thì đơn giản rồi nên mình
sẽ tập trung giải thích phần rex nhé. Rex command hay regex command là
một command giúp cho ta có thể trích xuất giá trị bên trong một field
thông qua biểu thức chính quy. Ngoài ra, rex còn có thể giúp ta tạo ra
một trường mới để tiện thao tác. Lưu ý, nếu bạn không cung cấp một
trường cụ thể cho rex thì mặc định rex sẽ lấy dữ liệu trong raw log.

Bây giờ mình sẽ giải thích lệnh rex ở câu query trên. Đầu tiên ta sẽ
khai báo trường **form\_data** cho rex.

Sau đó, ta trích giá trị của trường form\_data ở trong dấu nháy kép “”.

Ta sẽ tạo ra một trường mới tên là final, trường này sẽ mang giá trị sau
khi trích xuất của trường form\_data.

![](media/image47.png){width="6.5in" height="1.9604166666666667in"}

Tiếp theo, ta sẽ trích xuất giá trị của trường thông qua biểu thức chính
quy. Để test biểu thức chính quy, ta có thể truy cập
<https://regex101.com/> để thực hiện test. Phần test string thì mình
paste luôn đoạn giá trị của trường form\_data vào cho tiện test ( ͡° ͜ʖ
͡°).

![](media/image48.png){width="6.5in" height="2.441666666666667in"}

Tại câu query, ta sẽ trích xuất các giá trị đứng đằng sau passwd=

![](media/image49.png){width="6.5in" height="2.2041666666666666in"}

Tiếp theo, sử dụng \\w để lấy kí tự thuộc a-z, A-Z, 0-9 đứng đằng sau
dấu =

![](media/image50.png){width="6.5in" height="1.9125in"}

Nhưng hiện tại đoạn regex của mình mới chỉ lấy 1 kí tự đằng sau dấu =,
nhưng mình cần mật khẩu 6 kí tự nên mình thêm {6} để nó lấy chính xác đủ
6 kí tự bắt đầu từ sau dấu =

![](media/image51.png){width="6.5in" height="1.917361111111111in"}

OK, như vậy là đoạn biểu thức chính quy đã hoàn hiện. Giờ ta sẽ quay lại
câu query và thống kê giá trị của trường final là sẽ có được toàn bộ mật
khẩu có 6 kí tự.

![](media/image52.png){width="6.5in" height="2.6486111111111112in"}

Sau đó, ta sẽ xuất về 1 file csv để tiện tìm kiếm.

![](media/image53.png){width="6.5in" height="1.8493055555555555in"}

![](media/image54.png){width="6.5in" height="4.355555555555555in"}

Thực sự thì, mình thậm chí còn không biết Coldplay là nhóm nhạc nào luôn
chứ đừng nói là nghe nhạc ¯\\\_(ツ)\_/¯. Vì vậy, phải bê lên google tìm
thôi.

Sau khi search thì google có hiển thị một vài bài hát của Coldplay. Đành
tìm ở đây thôi chứ tìm hết list nhạc của nhóm này chắc ốm mất. Trong
đống bài hát của google hiển thị ra thì có 4 bài có tên chứa 6 kí tự.
Các bài lần lượt là **Yellow**, **Clocks**, **Sparks** và **Shiver**.

![](media/image55.png){width="6.5in" height="2.4618055555555554in"}

![](media/image56.png){width="5.875in" height="3.2186964129483813in"}

Bê tên 4 bài này qua file csv vừa tải về để tìm thì chỉ có bài Yellow là
match với giá trị trong file csv.

![](media/image57.png){width="6.674489282589676in"
height="2.736111111111111in"}

Đáp án là **Yellow**.

**\#116: What was the correct password for admin access to the content
management system running "imreallynotbatman.com"?**

Câu này yêu cầu tìm mật khẩu đúng của admin. Các cuộc tấn công
bruteforce sẽ thử 1 lần đối với tất cả các mật khẩu. Mật khẩu đúng sẽ là
mật khẩu xuất hiện nhiều hơn 1 lần vì attacker sẽ dùng nó để đăng nhập
vào hệ thống, có nghĩa là sẽ có hơn 1 lần provide bởi cùng 1 mật khẩu.

Sử dụng câu query bên dưới để tìm các lần provide mật khẩu với tài khoản
admin.

![](media/image58.png){width="6.5in" height="2.8881944444444443in"}

View event thì thấy có 2 source IP có từ admin trong form\_data. IP
40.80.148.42 có duy nhất 1 event.

![](media/image59.png){width="6.263888888888889in"
height="3.613781714785652in"}

Kiểm tra form\_data thì thấy đó là 1 lần provide mật khẩu là batman.

![](media/image60.png){width="6.5in" height="2.453472222222222in"}

Kiểm tra source IP với mật khẩu batman thì ta thấy cũng có 1 lần provide
nữa đối với IP 23.22.63.114. Dựa vào điều này, kịch bản rất có thể là IP
23.22.63.114 thực hiện bruteforce, khi dò đc ra mật khẩu đúng thì IP
40.80.148.42 sử dụng mật khẩu đó để đăng nhập.

![](media/image61.png){width="6.5in" height="2.3604166666666666in"}

Mật khẩu đúng mà cuộc tấn công bruteforce dò được chính là “batman”.

Đáp án là **batman**.

**\#117: What was the average password length used in the password brute
forcing attempt?**

Câu này yêu cầu tìm độ dài trung bình của các mật khẩu trong cuộc tấn
công bruteforce.

Câu này chỉ đơn giản là kĩ năng sử dụng query trong splunk mà thôi. Sử
dụng câu query bên dưới để search ra đáp án.

![](media/image62.png){width="6.5in" height="4.016666666666667in"}

Giải thích một chút nhé.

**rex** thì mình đã giải thích rồi, rex ở đây chỉ khác ở phần trường
được tạo sẽ là **pass** thay vì final và \\w+ thay vì \\w{6} thôi. Dấu +
sau \\w sẽ giúp ta lấy tất cả các kí tự thuộc a-z, A-z, 0-9 đằng sau dấu
=

![](media/image63.png){width="6.5in" height="1.9930555555555556in"}

**eval** sẽ giúp ta tính toán một biểu thức hoặc một giá trị cụ thể nào
đó và sau đó gán nó thành một trường dữ liệu mới. Ở câu query, mình dùng
**len** để đếm số kí tự của trường **pass** rồi gán nó thành 1 trường
tên là **length**.

Giá trị của trường **pass** chính là toàn bộ mật khẩu được sử dụng để
bruteforce với tất cả độ dài khác nhau. Ta dùng **len** để đếm số kí tự
của **pass** cũng chính là đếm số kí tự mật khẩu. Sau khi đếm được số kí
tự của tất cả mật khẩu, ta gán giá trị vừa đếm được thành một trường mới
là **length.**

![](media/image64.png){width="6.5in" height="3.265972222222222in"}

Cuối cùng mình sẽ dùng funtion **avg** để tính độ dài trung bình của
**length** là ra đáp án.

![](media/image65.png){width="6.5in" height="4.2243055555555555in"}

Đáp án là **6.177615571776156**, làm tròn còn **6**.

**\#118: How many seconds elapsed between the time the brute force
password scan identified the correct password and the compromised
login?**

Câu này yêu cầu tìm số giây trôi qua giữ lần quét được quét được mật
khẩu đúng và lần dùng mật khẩu đúng để đăng nhập.

Để tìm được số giây trôi qua, ta sẽ phải tìm phiên giao dịch giữa 2
event, event đầu khi quét được mật khẩu đúng và event cuối khi dùng mật
khẩu đúng để đăng nhập. Để làm được điều này, ta sẽ dùng đến
**transaction** command.

Đúng như tên gọi, **transaction** sẽ tìm các giao dịch dựa trên các sự
kiện đáp ứng các ràng buộc khác nhau. Ngoài ra, khi sử dụng
**transaction** sẽ thêm 2 trường nữa là **duration** và **eventcount**
vào raw log. Trường **duration** sẽ hiển thị mốc thời gian trôi qua
(tính bằng giây) giữa 2 event đầu cuối còn **eventcount** sẽ hiển thị số
lượng event trong phiên giao dịch.

Sử dụng câu query sau để tìm được đáp án.

![](media/image66.png){width="6.5in" height="3.10625in"}

Dùng **search** để ràng buộc tìm kiếm tại trường **pass** với chuỗi kí
tự **batman** là mật khẩu đúng xuất hiện trong lần scan và lần đăng
nhập.

Dùng **transaction** để tạo phiên giao dịch giữa 2 event có tồn tại
**batman**.

Sau khi tạo phiên giao dịch xong, ta sẽ tìm được số giây trôi qua giữa
lần scan được mật khẩu và lần đăng nhập tại giá trị của trường
**duration**.

Đề bài yêu cầu làm tròn đến 2 chữ số thập phân nên ta sẽ dùng **round**
để làm tròn giá trị của **duration** rồi gán cho nó thành một trường mới
với lệnh **eval.** Cuối cùng, ta thống kê giá trị sau khi làm tròn là sẽ
có được đáp án.

Đáp án là **92.17**

**\#119: How many unique passwords were attempted in the brute force
attempt?**

Câu này hỏi có bao nhiêu mật khẩu duy nhất đã được sử dụng trong cuộc
tấn công bruteforce.

Sử dụng funtion **dc** để bỏ đi những trường hợp lặp ta sẽ có được 412
event.

Funtions **dc** có tác dụng trả về tổng số các giá trị độc nhất.

![](media/image67.png){width="6.5in" height="3.5027777777777778in"}

Đáp án là **412**.

**Senario 2: Ransomware**

**\#200: What was the most likely IPv4 address of we8105desk on
24AUG2016?**

Câu này yêu cầu tìm IP của we8105desk. Câu này nếu bạn đọc phần giới
thiệu sẽ thấy user trong bài lab này có tên là Bob Smith. Vì vậy, câu
query sau sẽ được sử dụng để tìm ra đáp án.

![](media/image68.png){width="6.486111111111111in"
height="1.800310586176728in"}

![](media/image69.png){width="6.5in" height="1.6208333333333333in"}

Đáp án là **192.168.250.100**.

**\#201: Amongst the Suricata signatures that detected the Cerber
malware, which one alerted the fewest number of times? Submit ONLY the
signature ID value as the answer.**

Câu này yêu cầu tìm Suricata SID được phát hiện là có liên quan tới 1
malware tên là Cerber. Để làm được câu này ta sẽ tìm trong log source là
Suricata.

![](media/image70.png){width="6.5in" height="1.573611111111111in"}

Kiểm tra giá trị của trường vendor\_sid để lấy được giá trị SID. Theo đề
bài thì SID có số lần cảnh báo ít nhất chính là đáp án.

![](media/image71.png){width="7.121297025371828in"
height="2.7222222222222223in"}

Đáp án là **2816763**.

**\#202: What fully qualified domain name (FQDN) does the Cerber
ransomware attempt to direct the user to at the end of its encryption
phase?**

Câu này yêu cầu tìm tên miền mà người dùng bị điều hướng tới bởi malware
Cerber. Câu này chỉ cần kiểm tra trong log source stream:dns là ra. Các
bạn nhớ NOT những trường hợp query fail positive nhé.

![](media/image72.png){width="6.5in" height="2.327777777777778in"}

Đáp án là **cerberhhyed5frqa.xmfir0.win**

**\#203: What was the first suspicious domain visited by we8105desk on
24AUG2016?**

Câu này yêu cầu tìm tên miền độc hại đầu tiên được truy cập bởi
we8105desk. Câu này đơn giản thôi, từ kết quả câu 202, các bạn thống kê
thêm timestamp và ấn vào chữ timestamp ở đầu để sắp xếp lại kết quả sao
cho event sớm nhất sẽ nhảy lên đầu.

![](media/image73.png){width="6.5in" height="2.66875in"}

Ta thấy có tên miền solidaritedeproximite.org được truy cập vào 16:48
ngày 24-08-2016.

Đáp án là **solidaritedeproximite.org**

**\#204: During the initial Cerber infection a VB script is run. The
entire script from this execution, pre-pended by the name of the
launching .exe, can be found in a field in Splunk. What is the length in
characters of the value of this field?**

Câu này cho ta biết trong quá trình lây nhiễm, có một file VB script
được khởi chạy. Tất cả đoạn script trong file VB đó đều đã được chờ đợi
trước bởi một file .exe đang chạy trong hệ thống. Ta có thể tìm thấy các
đoạn script được đợi trước bởi file .exe đó trong giá trị của một field
nào đó trong Splunk. Nhiệm vụ của ta là đi tìm field đó và đếm độ dài kí
tự của giá trị trong field.

Sử dụng đoạn query dưới hình để tìm các file VB script được khởi chạy và
ta tìm có tất cả là 4 event.

![](media/image74.png){width="6.5in" height="0.7840277777777778in"}

Sau một hồi tìm kiếm, mình tìm thấy một trường là **cmdline**, trường
này sẽ xác định các đoạn command đã được khởi chạy. Trong đó, có một
đoạn giá trị mình thấy rất khả nghi, đoạn giá trị đó rất dài và sau khi
đọc qua thì mình khá chắc chắn đây chính là các đoạn script của file VB
script được khởi chạy.

![](media/image75.png){width="6.5in" height="2.0861111111111112in"}

![](media/image76.png){width="6.5in" height="2.5409722222222224in"}

Oops, quên Active Windows ( ͡° ͜ʖ ͡°)

OK, giờ ta đã tìm được giá trị của trường có chứa các đoạn script của
file VB script được khởi chạy, nhưng làm thế nào để đếm số kí tự trong
trường bây giờ? Đơn giản thôi, chỗ này ta dùng **rex** kết hợp với
function **len** là xong. Dùng câu query dưới đây để có được kết quả
cuối cùng.

![](media/image77.png){width="6.5in" height="1.051388888888889in"}

Giải thích một chút nhé. Trường mới được tạo ra bởi **rex** là cmdline,
ta dùng **rex** để lọc trong raw log và lấy tất cả các kí tự đứng đằng
sau cmdline. Dấu **.** sẽ lấy tất cả mọi loại kí tự, chỉ trừ ngắt dòng.
Vì để 1 dấu **.** thì sẽ chỉ lấy 1 kí tự nên ta thêm dấu **\*** để lấy
toàn bộ kí tự kế tiếp cho đến khi hết câu.

![](media/image78.png){width="6.5in" height="2.6597222222222223in"}

Tiếp đến, dùng **len** để đếm số kí tự của trường cmdline được tạo ra
bởi **rex** và gán giá trị của **len** thành một trường mới có tên là
length.

Cuối cùng, ta thống kê length và cmdline ra là sẽ có được đáp án.

![](media/image79.png){width="6.5in" height="2.404861111111111in"}

Đáp án là **4490.**

**\#205: What is the name of the USB key inserted by Bob Smith?**

Câu này yêu cầu tìm tên của USB key của Bob Smith. Câu này mình phải
google vì mình không biết phải search như nào luôn.

Search google với từ khóa là “search usb key in splunk” và truy cập dòng
đầu tiên.

![](media/image80.png){width="6.5in" height="2.7916666666666665in"}

Về cơ bản, bài viết này sẽ giúp cho chúng ta biết phải search như thế
nào để tìm được tên của thiết bị USB và giải thích về câu search đó.

Để search được tên của USB device thì ta sẽ phải search trong log source
là Windows Registry Logs. Sau đó search theo từ khóa friendlyname, từ
khóa này được sử dụng với mục đích tìm giá trị registry dành riêng cho
thiết bị USB.

Sau khi search với cả 2 điều kiện trên, ta sẽ tìm được tên thiết bị USB
tại trường registry\_value\_data.

![](media/image81.png){width="6.5in" height="2.8118055555555554in"}

Search trên splunk ta có kết quả như sau.

![](media/image82.png){width="4.319444444444445in"
height="3.558468941382327in"}

Đáp án là **MIRANDA\_PRI**

**\#206: Bob Smith's workstation (we8105desk) was connected to a file
server during the ransomware outbreak. What is the IPv4 address of the
file server?**

Câu này yêu cầu tìm IP của file server mà host we8105desk kết nối đến.
Câu này khá đơn giản, ta dùng câu truy vấn dưới đây và tìm trong trường
key\_path để biết IP của file server được truy cập. Về cơ bản, ta sẽ kết
hợp việc tìm trong registry với từ khóa fileshare giống như cách ta
search với từ khóa friendlyname ở câu 205 để biết được IP của file
server.

![](media/image83.png){width="6.555555555555555in"
height="3.8752023184601927in"}

Đáp án là **192.168.250.20**

**\#207: How many distinct PDFs did the ransomware encrypt on the remote
file server?**

Câu này yêu cầu tìm số lượng file PDF đã mã hóa ransomeware trên remote
file server.

Search thử xem có gì liên quan đến đuôi .pdf không.

![](media/image84.png){width="3.2604166666666665in" height="2.15625in"}

Ồ 865 events. Sau một hồi tìm kiếm, mình tìm được một trường là
Relative\_Target\_Name. Trường này sẽ cung cấp tên của tệp hoặc thư mục
đích được truy cập trong môi trường chia sẻ mạng.

![](media/image85.png){width="6.5in" height="4.1194444444444445in"}Ồ,
rất nhiều file pdf ở đây. Đặt giới hạn chỉ tìm kiếm đối với file có đuôi
pdf cho trường Relative\_Target\_Name và thống kê giá trị của trường ta
được kết quả như sau.

![](media/image86.png){width="5.368055555555555in"
height="3.7111865704286964in"}

OK như vậy là rõ rồi, có 257 file pdf.

Đáp án là **257**

**\#208: The VBscript found in question 204 launches 121214.tmp. What is
the ParentProcessId of this initial launch?**

Câu này cho ta thông tin là Vbscript ở câu 204 có chạy 1 file là
121214.tmp và nhiệm vụ của ta là tìm ParentProcessId của lần khởi chạy
này.

Quay lại kết quả của câu 204 ta sẽ thấy một cmdline khởi chạy file
121214.tmp ở ngay phía trên.

![](media/image87.png){width="6.5in" height="2.3402777777777777in"}

Search event của cmdline đó và kiểm tra trường ParentProcessId để lấy
được đáp án cho câu này.

![](media/image88.png){width="6.5in" height="2.3361111111111112in"}

Đáp án là **3968**.

**\#209: The Cerber ransomware encrypts files located in Bob Smith's
Windows profile. How many .txt files does it encrypt?**

Câu này cho ta biết thông tin là ransomware mã hóa file được lưu trong
windows profile của Bob Smith. Nhiệm vụ của ta là tìm số lượng file .txt
bị mã hóa. Với câu query dưới đây, ta sẽ tìm toàn bộ file txt nằm trong
path C:\\Users\\bob.smith.WAYNECORPINC\\. Sau đó loại bỏ toàn bộ giá trị
bị lặp với **dc** và thống kê kết quả cuối cùng ra màn hình.

![](media/image89.png){width="6.5in" height="4.048611111111111in"}

Đáp án là **406**.

**\#210: The malware downloads a file that contains the Cerber
ransomware cryptor code. What is the name of that file?**

Câu này cho ta biết rằng malware đã download 1 file có chứa crytor code
của ransomware Cerber. Nhiệm vụ của ta là tìm tên file đó.

Được biết malware đã download 1 file từ internet về nên ta sẽ loại bỏ
các URL fail postive và tìm trong những url mà IP của nạn nhân truy vấn
tới. Thông kê theo dest và url ta sẽ có được kết quả như hình bên dưới.

![](media/image90.png){width="6.5in" height="3.3055555555555554in"}

Hmm, có 16 event, thử kiểm tra chỗ URL này coi sao. Sau khi kiểm tra,
mình nhận thấy có 1 truy vấn tới file mhtr.jpg tại tên miền
solidaritedeproximite.org là tên miền độc hại đầu tiên được truy cập bởi
nạn nhân.

![](media/image91.png){width="4.411924759405075in"
height="3.746836176727909in"}

Giữa một “mả” tên miền hợp lệ thì lại “tòi” ra 1 ông là tên miền độc hại
đầu tiên được truy cập. Có thể chắc chắn rằng malware đã download file
mhtr.jpg về từ tên miền solidaritedeproximite.org. Đây đích thị là file
mà chúng ta đang cần tìm.

Đáp án là **mhtr.jpg**

**\#211: Now that you know the name of the ransomware's encryptor file,
what obfuscation technique does it likely use?**

Câu này yêu cầu chúng ta tìm ra kỹ thuật obfuscation (kỹ thuật xáo trộn)
mà tệp mã hóa ransomware sử dụng để che dấu bản thân sau khi đã biết tên
tệp. Câu này 1000 điểm nhưng cũng rất dễ để có được đáp án nếu bạn tỉnh.

OK, tên tệp là mhtr.jpg. Nó có đuôi là .jpg nên tất nhiên nó là một file
ảnh. Vậy kĩ thuật obfuscation nào liên quan đến các file ảnh?

Đúng rồi đấy.

Đáp án là **steganography**
