import os
import re
from datetime import datetime

_KEYWORD_STOPWORDS = {
    "the", "and", "for", "with", "this", "that", "from", "into",
    "note", "notes", "study", "markdown", "vault", "root"
}


def _extract_keywords(title: str, folder_name: str, tags: list[str], content: str) -> list[str]:
    source_text = " ".join([title, folder_name, " ".join(tags), content]).lower()
    tokens = re.findall(r"[a-zA-Z0-9가-힣][a-zA-Z0-9가-힣_+.-]{1,}", source_text)
    keywords = []
    for token in tokens:
        if token in _KEYWORD_STOPWORDS or token.isdigit():
            continue
        if token not in keywords:
            keywords.append(token)
        if len(keywords) == 12:
            break
    return keywords

def parse_markdown_bytes(file_bytes: bytes, rel_path: str, mtime_timestamp: float = None):
    """
    [MUST] 6.2 / 6.3 - 메모리 상의 마크다운 바이트 데이터를 파싱하여 필수 정보를 추출하는 함수
    """
    # 1. 바이트를 바로 텍스트로 변환 (팀원분 가이드 반영)
    content = file_bytes.decode("utf-8", errors="replace")

    # 2. 파일명 및 상위 폴더명 추출 [MUST]
    file_name = os.path.basename(rel_path)
    # rel_path가 'CTF/web/xss-writeup.md' 라면 'web' 추출
    parent_dir = os.path.dirname(rel_path)
    folder_name = os.path.basename(parent_dir) if parent_dir else "Root"

    # 3. 제목 추출 (# 제목 문법 탐색) [MUST]
    title_match = re.search(r'^#\s+(.+)$', content, re.MULTILINE)
    title = title_match.group(1).strip() if title_match else file_name.replace('.md', '')

    # 4. 태그 추출 (본문 내 #태그명 형태 탐색) [MUST]
    tags = re.findall(r'#([a-zA-Z0-9가-힣_-]+)', content)
    keywords = _extract_keywords(title, folder_name, tags, content)

    # 5. 작성일 또는 수정일 처리 [MUST]
    # 팀원분이 시간을 넘겨주면 변환하고, 없으면 현재 시간을 기본값으로 사용합니다.
    if mtime_timestamp is not None:
        file_date = datetime.fromtimestamp(mtime_timestamp).strftime('%Y-%m-%d %H:%M:%S')
    else:
        file_date = datetime.now().strftime('%Y-%m-%d %H:%M:%S')

    # 기획서 MUST 등급 요구사항 구조화 후 반환 [MUST]
    return {
        "file_name": file_name,        # [MUST] 파일명
        "file_path": rel_path,         # [MUST] ZIP 내 상대 경로
        "folder_name": folder_name,    # [MUST] 폴더명
        "title": title,                # [MUST] 제목
        "tags": list(set(tags)),       # [MUST] 태그 목록 (중복 제거)
        "keywords": keywords,          # 분석 API 연동용 키워드
        "date": file_date,             # [MUST] 작성일 또는 수정일
        "content": content             # [MUST] Markdown 본문 전체
    }

def parse_all_markdowns_from_bytes(zip_file_entries: list[dict]):
    """
    [MUST] 6.1 / 6.2 - 메모리 상에 추출된 파일 바이트 리스트를 받아 
    .md 파일만 필터링하고 전부 파싱하여 리스트를 반환하는 함수
    
    zip_file_entries 예시 구조:
    [
        {"rel_path": "CTF/web/xss.md", "bytes": b"...", "mtime": 1716531234.0},
        {"rel_path": "images/photo.png", "bytes": b"...", "mtime": 1716531235.0}
    ]
    """
    parsed_results = []
    
    for entry in zip_file_entries:
        rel_path = entry.get("rel_path", "")
        
        # 1. .md 확장자만 분석 대상으로 필터링 [MUST]
        if rel_path.endswith('.md'):
            file_bytes = entry.get("bytes")
            mtime = entry.get("mtime")
            
            try:
                # 앞서 수정한 바이트 전용 파싱 함수 호출
                data = parse_markdown_bytes(file_bytes, rel_path, mtime_timestamp=mtime)
                parsed_results.append(data)
            except Exception as e:
                print(f"메모리 파일 파싱 에러 발생 ({rel_path}): {e}")
                
    return parsed_results
