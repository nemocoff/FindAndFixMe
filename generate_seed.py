import struct
import os

def generate_american_option_seed(output_path="seed_american_option.bin"):
    # 1. 루프 횟수 (uint16_t, 2바이트) -> 1번 돌도록 세팅
    length_bytes = struct.pack("<H", 1)
    
    # 2. 옵션 타입 (uint8_t, 1바이트) -> Call 옵션
    type_byte = struct.pack("B", 1)
    
    # 3. strike (double, 8바이트) -> 100.0
    strike_bytes = struct.pack("<d", 100.0)
    
    # 4. s (spot 주가) (double, 8바이트) -> 100.0
    spot_bytes = struct.pack("<d", 100.0)
    
    # 5. q (배당률) (double, 8바이트) -> 0.01 (1%)
    q_bytes = struct.pack("<d", 0.01)
    
    # 6. r (무위험 이자율) (double, 8바이트) -> 0.03 (3%)
    r_bytes = struct.pack("<d", 0.03)
    
    # 7. t (잔존 만기) (double, 8바이트) -> 1.0 (1년)
    t_bytes = struct.pack("<d", 1.0)
    
    # 8. v (변동성) (double, 8바이트) -> 0.20 (20%)
    v_bytes = struct.pack("<d", 0.20)
    
    # 모든 바이트 결합 (총 51바이트)
    seed_data = (
        length_bytes + 
        type_byte + 
        strike_bytes + 
        spot_bytes + 
        q_bytes + 
        r_bytes + 
        t_bytes + 
        v_bytes
    )
    
    # 바이너리 파일로 저장
    with open(output_path, "wb") as f:
        f.write(seed_data)
        
    print(f"성공적으로 시드 파일 생성 완료! -> {output_path} (크기: {len(seed_data)} 바이트)")

if __name__ == "__main__":
    generate_american_option_seed()
