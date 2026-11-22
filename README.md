# TBCC VPN for Android

[下载 Android 64 位 APK · Download for Android (ARM64) · Скачать для Android (ARM64)](https://github.com/tbccvpn/TBCC-VPN-Downloads/releases/latest/download/TBCC-VPN-arm64-v8a.apk)

[通用 APK · Universal APK · Универсальный APK](https://github.com/tbccvpn/TBCC-VPN-Downloads/releases/latest/download/TBCC-VPN-universal.apk) · [所有版本 · All releases · Все версии](https://github.com/tbccvpn/TBCC-VPN-Downloads/releases)

### 简体中文

支持 Android 9 及更高版本。大多数手机请选择 64 位 APK。如果不确定设备支持哪种架构，请选择通用 APK。下载后，在手机上打开文件并按照 Android 的提示安装。也可以从 [TBCC VPN 官网](https://vpn.tbcc.com/setup/tbcc) 下载。

账号暂时没有 VPN 访问权限时，可打开「套餐、设备和支持」，在「每日免费试用」中点「开启今天的免费时段」。从首次开启当天起，连续 30 个自然日每天可开启一次，每次最多 60 分钟，最晚在北京时间午夜结束。断开后仍会继续计时，到期前可重新连接。

年度订阅限一台个人设备，价格为 10 美元，通过 TON 网络一次性支付等值的 TBCC，有效期 372 天。

### English

Requires Android 9 or later. Choose the ARM64 APK for most phones, or the universal APK if you are unsure which processor your device uses. Open the downloaded file on your phone and follow the Android installation prompts. You can also download the app from the [TBCC VPN website](https://vpn.tbcc.com/setup/tbcc).

If your account has no active VPN access, open the plans section and tap **Start today’s free session**. You can start one session per day for 30 consecutive calendar days, beginning on the day you first start the trial. Each session lasts up to 60 minutes and ends by midnight Beijing time. The timer keeps running if you disconnect. You can reconnect until the session ends.

An annual subscription covers one personal device for 372 days. Pay once in TBCC on the TON network, at the equivalent of US$10.

### Русский

Требуется Android 9 или новее. Для большинства телефонов подойдёт APK для ARM64. Если не знаете архитектуру устройства, скачайте универсальный APK. Откройте скачанный файл на телефоне и следуйте подсказкам Android. Приложение также доступно на [сайте TBCC VPN](https://vpn.tbcc.com/setup/tbcc).

Если в аккаунте ещё нет доступа к VPN, откройте «Тарифы, устройства и поддержка» и нажмите **«Начать бесплатный сеанс»**. Со дня первого запуска доступен один сеанс в день в течение 30 календарных дней. Он длится до 60 минут и заканчивается не позднее полуночи по Пекину. Если отключиться, таймер продолжит идти. До конца сеанса можно подключиться снова.

Годовая подписка действует на одном личном устройстве 372 дня. Оплата разовая, токенами TBCC в сети TON на сумму 10 долларов США.

### 应用内更新 · In-app updates · Обновления внутри приложения

支持此功能的版本可通过 TBCC 官网和 GitHub 检查更新，无需 GitHub 账户。应用会验证更新目录的 TBCC 签名、APK 校验和及安装签名。请按 Android 的提示完成安装；无需卸载应用或重新购买订阅。测试版与正式版使用各自的更新渠道。

Supported app versions can check updates through TBCC and GitHub without a GitHub account. The app verifies the TBCC-signed catalog, APK checksum and installation signature. Follow Android’s installation prompts; keep the existing app and subscription. Test and public builds use separate update channels.

В поддерживаемых версиях приложение проверяет обновления через TBCC и GitHub без аккаунта GitHub. Проверяются подпись каталога TBCC, контрольная сумма APK и подпись приложения. Следуйте подсказкам Android; удалять приложение и покупать подписку заново не требуется. Тестовые и обычные сборки обновляются по своим каналам.

Каталог: ветка [`updates-v1`](https://github.com/tbccvpn/TBCC-VPN-Downloads/tree/updates-v1), файлы `android/v1/stable.json` и, после активации тестового канала, `development.json`. Workflow копирует только проверенные подписанные данные, обновляя зеркало каждые 30 минут. Приватный ключ остаётся на сервере TBCC; GitHub не меняет политику выпуска. Просроченные или подменённые данные приложение отклоняет.

### Release notes · Описание выпуска

[Шаблон описания релиза · Release template · 版本说明模板](RELEASE_TEMPLATE.md)

Для нового выпуска укажите версию без префикса `v`, код сборки и изменения, которые заметит пользователь. Зеркало подставляет версию в GitHub-ссылки, добавляет страницу установки TBCC и берёт текст изменений из подписанных сведений о выпуске, когда он доступен.
