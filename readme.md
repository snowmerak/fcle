# file capsule

## 설치

먼저 golang을 설치해야합니다. https://go.dev/dl/ 에서 사용하는 환경에 맞는 배포판을 설치하세요. 각 환경에 따른 각기 다른 패키지 매니저를 이용할 수도 있습니다.

```bash
// macos
brew install go

// arch
yay -S go

// debian & ubuntu
apt install go

// fedora & centos & redhat
dnf install go

// openSUSE
zypper install go
```

## 암호화

옵션 -enc를 넣음으로 파일을 암호화합니다.

```bash
filecapsule -enc -file=text.zip
```

그러면 같은 디렉토리에 test.zip.fncl 파일이 생성됩니다.

### 비밀번호 지정

```bash
filecapsule -enc -pw=custom_password -file=text.zip
```

-pw 플래그를 지정함으로 사용자 지정 비밀번호를 사용할 수 있습니다.

## 복호화

옵션에 -dec를 줌으로 파일을 복호화할 수 있습니다.

```bash
filecapsule -dec -file=text.zip.fncl
```

마찬가지로 같은 디렉토리에 .fncl 확장자를 제거한 파일이 생성됩니다.

### 비밀번호 지정

```bash
filecapsule -dec -pw=custom_password -file=text.zip.fncl
```

마찬가지로 -pw 플래그를 지정하여 전달합니다.