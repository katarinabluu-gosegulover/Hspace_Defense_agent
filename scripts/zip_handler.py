import io #디스크 저장 없이 파일을 처리하기 위해서 씀
import zipfile
from datetime import datetime
from fastapi import HTTPException


def _as_zip_stream(zip_file):
    if isinstance(zip_file, (bytes, bytearray)):
        return io.BytesIO(zip_file)
    return zip_file


def extract_md_files(zip_file):
    zip_stream = _as_zip_stream(zip_file)
    md_files={} # 압축해제 후 결과를 반환하기 위해서 딕셔너리 생성함  
    if zipfile.is_zipfile(zip_stream):   # 1. ZIP 검증
         zip_stream.seek(0)
         # 2. 압축 해제
         # 3. .md 파일만 필터링
         with zipfile.ZipFile(zip_stream, 'r') as zipObj:  #일단 코드에서 연 zip파일은 zipObj라고 명시함. 나중에 parser랑 통일 필요할듯
            for fileName in zipObj.namelist():
              if fileName.endswith(".md"):
                content = zipObj.read(fileName)
                 # 4. 결과 반환
                md_files[fileName] = content
         return md_files
                  
    else:  
       raise HTTPException(status_code=400, detail="ZIP 파일이 아닙니다") #프론트로 에러를 보내줌 


def extract_md_entries(zip_file):
    zip_stream = _as_zip_stream(zip_file)
    if not zipfile.is_zipfile(zip_stream):
        raise HTTPException(status_code=400, detail="ZIP 파일이 아닙니다")

    zip_stream.seek(0)
    entries = []
    with zipfile.ZipFile(zip_stream, "r") as zip_obj:
        for info in zip_obj.infolist():
            if info.is_dir() or not info.filename.lower().endswith(".md"):
                continue

            mtime = datetime(*info.date_time).timestamp()
            entries.append({
                "rel_path": info.filename,
                "bytes": zip_obj.read(info.filename),
                "mtime": mtime,
            })

    return entries
  
# 작동 테스트  
if __name__ == "__main__":
    result = extract_md_files("test.zip")
    for filename, content in result.items():
        print(filename, ":", content.decode("utf-8"))  # 디코딩 추가

    
    
