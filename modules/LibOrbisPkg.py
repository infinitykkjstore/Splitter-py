#!/usr/bin/env python3
"""
PKG Metadata Extractor - Extrai metadados de PKG sem baixar arquivo completo
Baseado em LibOrbisPkg e replica comportamento do DirectPackageInstaller

Uso:
    python give_meta.py --url <PKG_URL>
    python give_meta.py --url https://cdn.com/game.pkg --output metadata.json
"""

import sys
import argparse
import requests
import struct
import json
from typing import Dict, Any, List
import urllib3

# Desabilitar warnings de SSL
urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)


class PKGMetadataExtractor:
    """
    Extrator de metadados de PKG via HTTP Range Requests
    Baseado em LibOrbisPkg/PKG/PkgReader.cs e Pkg.cs
    """
    
    # Constantes (Pkg.cs linhas 40-70)
    PKG_MAGIC = b'\x7FCNT'
    PKG_CONTENT_ID_SIZE = 0x30
    PKG_HEADER_SIZE = 0x5A0
    HASH_SIZE = 0x20
    PKG_TABLE_ENTRY_SIZE = 0x20
    
    # Entry IDs (baseado em EntryId enum)
    ENTRY_ID_METAS = 0x1280
    ENTRY_ID_PARAM_SFO = 0x1000
    ENTRY_ID_ICON0_PNG = 0x1200
    
    def __init__(self, url: str, verbose: bool = False):
        self.url = url
        self.verbose = verbose
        self.session = requests.Session()
        
        # Replicar User-Agent do DPI
        self.session.headers.update({
            'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36'
        })
        self.session.verify = False
        self.session.headers.update({'Connection': 'close'})
    
    def log(self, message: str, level: str = "INFO"):
        if self.verbose or level == "ERROR":
            prefix = {"INFO": "[INFO]", "SUCCESS": "[OK]", "ERROR": "[ERROR]", "WARN": "[WARN]", "DEBUG": "[DEBUG]"}.get(level, "[*]")
            print(f"{prefix} {message}")
    
    def fetch_range(self, start: int, end: int, retry: int = 0) -> bytes:
        """Baixa range via HTTP (replica NetworkStream.HttpReader)"""
        try:
            headers = {'Range': f'bytes={start}-{end}'}
            self.log(f"Fetching bytes {start}-{end} ({end-start+1} bytes)", "DEBUG")
            
            response = self.session.get(self.url, headers=headers, timeout=30, allow_redirects=True)
            
            if response.status_code == 416:
                self.log("Range not satisfiable, downloading full range...", "WARN")
                response = self.session.get(self.url, timeout=30, allow_redirects=True)
                if response.status_code == 200:
                    return response.content[start:end+1]
            
            if response.status_code not in [200, 206]:
                raise Exception(f"HTTP {response.status_code}")
            
            return response.content
        except Exception as e:
            if retry < 3:
                self.log(f"Erro: {e}, retry ({retry+1}/3)...", "WARN")
                import time
                time.sleep(retry * 0.5)
                return self.fetch_range(start, end, retry + 1)
            else:
                raise Exception(f"Failed after 3 attempts: {e}")
    
    def extract_metadata(self) -> Dict[str, Any]:
        """Extrai metadados completos do PKG"""
        self.log("Iniciando extração de metadados...", "INFO")
        
        # 1. Ler e parsear header (PkgReader.cs linha 90-181)
        self.log("Lendo header do PKG...", "INFO")
        header_data = self.fetch_range(0, self.PKG_HEADER_SIZE - 1)
        header = self._parse_header(header_data)
        
        # 2. Ler header digest e signature (PkgReader.cs linhas 15-17)
        digest_sig_data = self.fetch_range(0xFE0, 0x10FF)
        header['header_digest'] = digest_sig_data[0:32].hex().upper()
        header['header_signature'] = digest_sig_data[32:].hex().upper()
        
        # 3. Ler Entry Table (PkgReader.cs linhas 18-23)
        self.log("Lendo Entry Table...", "INFO")
        entries = self._read_entry_table(header)
        
        # 4. Processar entries (PkgReader.cs linhas 31-86)
        pkg_info = header.copy()
        pkg_info['entries'] = entries
        
        # 5. Extrair param.sfo DA ENTRY TABLE (não do METAS!)
        # PkgReader.cs linha 41-45: case EntryId.PARAM_SFO (0x1000)
        self.log("Procurando param.sfo...", "INFO")
        param_sfo_entry = next((e for e in entries if e['id'] == 0x1000), None)
        if param_sfo_entry:
            self.log("Extraindo param.sfo...", "INFO")
            sfo_params = self._read_param_sfo_from_entry(header, param_sfo_entry)
            pkg_info['params'] = sfo_params
            pkg_info['title'] = sfo_params.get('TITLE', '')
            pkg_info['title_id'] = sfo_params.get('TITLE_ID', '')
            pkg_info['category'] = sfo_params.get('CATEGORY', '')
            pkg_info['system_ver'] = sfo_params.get('SYSTEM_VER', 0)
            pkg_info['app_type'] = sfo_params.get('APP_TYPE', 0)
            self.log(f"✓ SFO: {pkg_info['title']}", "SUCCESS")
        else:
            self.log("⚠ param.sfo não encontrado", "WARN")
            pkg_info['params'] = {}
            pkg_info['title'] = ''
            pkg_info['title_id'] = ''
            pkg_info['category'] = ''
        
        # 6. Extrair ícone DA ENTRY TABLE (EntryId.ICON0_PNG = 0x1200)
        self.log("Procurando ícone...", "INFO")
        icon_entry = next((e for e in entries if e['id'] == 0x1200), None)
        if icon_entry:
            icon_data = self._read_icon_from_entry(header, icon_entry)
            pkg_info['icon_data'] = icon_data
            pkg_info['icon_size'] = len(icon_data)
            self.log(f"✓ Ícone extraído ({len(icon_data)} bytes)", "SUCCESS")
        else:
            pkg_info['icon_data'] = None
            pkg_info['icon_size'] = 0
            self.log("ℹ PKG sem ícone (comum em updates/patches)", "INFO")
        
        # 7. Metadata adicional
        pkg_info['content_type_friendly'] = self._get_friendly_content_type(pkg_info.get('category', ''))
        pkg_info['bgft_package_type'] = self._get_bgft_package_type(pkg_info.get('category', ''))
        
        self.log("✓ Extração completa!", "SUCCESS")
        return pkg_info
    
    def _parse_header(self, data: bytes) -> Dict[str, Any]:
        """Parse header PKG (Pkg

Reader.cs linhas 90-181)"""
        header = {}
        
        # Verificar magic (linha 94-96)
        magic = data[0:4]
        if magic != self.PKG_MAGIC:
            raise Exception(f"Invalid PKG magic: {magic.hex()}")
        
        # Extrair campos conforme offsets do LibOrbisPkg
        header['magic'] = magic.decode('ascii', errors='ignore')
        header['flags'] = struct.unpack('>I', data[0x04:0x08])[0]
        header['unk_0x08'] = struct.unpack('>I', data[0x08:0x0C])[0]
        header['unk_0x0C'] = struct.unpack('>I', data[0x0C:0x10])[0]
        header['entry_count'] = struct.unpack('>I', data[0x10:0x14])[0]
        header['sc_entry_count'] = struct.unpack('>H', data[0x14:0x16])[0]
        header['entry_count_2'] = struct.unpack('>H', data[0x16:0x18])[0]
        header['entry_table_offset'] = struct.unpack('>I', data[0x18:0x1C])[0]
        header['main_ent_data_size'] = struct.unpack('>I', data[0x1C:0x20])[0]
        header['body_offset'] = struct.unpack('>Q', data[0x20:0x28])[0]
        header['body_size'] = struct.unpack('>Q', data[0x28:0x30])[0]
        
        # Content ID (linha 118)
        content_id_bytes = data[0x40:0x40 + self.PKG_CONTENT_ID_SIZE]
        header['content_id'] = content_id_bytes.decode('ascii', errors='ignore').rstrip('\x00')
        
        # Outros campos importantes
        header['drm_type'] = struct.unpack('>I', data[0x70:0x74])[0]
        header['content_type'] = struct.unpack('>I', data[0x74:0x78])[0]
        header['content_flags'] = struct.unpack('>I', data[0x78:0x7C])[0]
        header['promote_size'] = struct.unpack('>I', data[0x7C:0x80])[0]
        header['version_date'] = struct.unpack('>I', data[0x80:0x84])[0]
        header['version_hash'] = struct.unpack('>I', data[0x84:0x88])[0]
        
        # Package size e PFS info (linhas 154-180)
        header['package_size'] = struct.unpack('>Q', data[0x430:0x438])[0]
        header['pfs_image_count'] = struct.unpack('>I', data[0x404:0x408])[0]
        header['pfs_flags'] = struct.unpack('>Q', data[0x408:0x410])[0]
        header['pfs_image_offset'] = struct.unpack('>Q', data[0x410:0x418])[0]
        header['pfs_image_size'] = struct.unpack('>Q', data[0x418:0x420])[0]
        header['pfs_image_digest'] = data[0x440:0x460].hex().upper()
        
        self.log(f"Package Size: {header['package_size']} bytes", "DEBUG")
        self.log(f"Content ID: {header['content_id']}", "DEBUG")
        self.log(f"Entry Count: {header['entry_count']}", "DEBUG")
        
        return header
    
    def _read_entry_table(self, header: Dict[str, Any]) -> List[Dict[str, Any]]:
        """Lê Entry Table (PkgReader.cs MetaEntry.Read)"""
        table_offset = header['entry_table_offset']
        table_size = header['entry_count'] * self.PKG_TABLE_ENTRY_SIZE
        
        entry_data = self.fetch_range(table_offset, table_offset + table_size - 1)
        
        entries = []
        for i in range(header['entry_count']):
            offset = i * self.PKG_TABLE_ENTRY_SIZE
            entry_bytes = entry_data[offset:offset + self.PKG_TABLE_ENTRY_SIZE]
            
            entry = {
                'id': struct.unpack('>I', entry_bytes[0x00:0x04])[0],
                'filename_offset': struct.unpack('>I', entry_bytes[0x04:0x08])[0],
                'flags1': struct.unpack('>I', entry_bytes[0x08:0x0C])[0],
                'flags2': struct.unpack('>I', entry_bytes[0x0C:0x10])[0],
                'data_offset': struct.unpack('>I', entry_bytes[0x10:0x14])[0],
                'data_size': struct.unpack('>I', entry_bytes[0x14:0x18])[0],
            }
            entries.append(entry)
        
        self.log(f"✓ {len(entries)} entries lidas", "DEBUG")
        return entries
    
    def _read_param_sfo_from_entry(self, header: Dict[str, Any], entry: Dict[str, Any]) -> Dict[str, Any]:
        """Lê param.sfo da entry table principal (PkgReader.cs linha 42-44)"""
        # PkgReader.cs linha 42: s.Position = entry.DataOffset
        # O DataOffset JÁ é absoluto, NÃO somar com body_offset!
        sfo_offset = entry['data_offset']
        sfo_size = entry['data_size']
        
        self.log(f"SFO offset: 0x{sfo_offset:X}, size: {sfo_size}", "DEBUG")
        
        sfo_data = self.fetch_range(sfo_offset, sfo_offset + sfo_size - 1)
        
        # Validar magic
        magic = sfo_data[0:4]
        self.log(f"SFO magic: {magic.hex()}", "DEBUG")
        
        if magic != b'\x00PSF':
            raise Exception(f"Invalid SFO magic: {magic.hex()}")
        
        # Parse SFO header
        key_table_offset = struct.unpack('<I', sfo_data[8:12])[0]
        data_table_offset = struct.unpack('<I', sfo_data[12:16])[0]
        tables_entries = struct.unpack('<I', sfo_data[16:20])[0]
        
        self.log(f"SFO entries: {tables_entries}", "DEBUG")
        
        params = {}
        for i in range(tables_entries):
            entry_offset = 20 + (i * 16)
            entry_bytes = sfo_data[entry_offset:entry_offset + 16]
            
            key_offset = struct.unpack('<H', entry_bytes[0:2])[0]
            param_fmt = struct.unpack('<H', entry_bytes[2:4])[0]
            param_len = struct.unpack('<I', entry_bytes[4:8])[0]
            data_offset_rel = struct.unpack('<I', entry_bytes[12:16])[0]
            
            # Ler nome da chave
            key_start = key_table_offset + key_offset
            key_end = sfo_data.index(b'\x00', key_start)
            key_name = sfo_data[key_start:key_end].decode('ascii')
            
            # Ler valor
            value_start = data_table_offset + data_offset_rel
            
            if param_fmt == 0x0004:  # UTF-8 string (SfoEntryType.Utf8)
                try:
                    value_end = sfo_data.index(b'\x00', value_start)
                    value = sfo_data[value_start:value_end].decode('utf-8', errors='ignore')
                except:
                    # Se não encontrar null, ler param_len bytes
                    value_bytes = sfo_data[value_start:value_start + param_len]
                    value = value_bytes.decode('utf-8', errors='ignore').rstrip('\x00')
            elif param_fmt == 0x0404:  # int32 (SfoEntryType.Integer)
                value = struct.unpack('<I', sfo_data[value_start:value_start + 4])[0]
            else:
                # Outros formatos: tentar decodificar como string UTF-8
                value_bytes = sfo_data[value_start:value_start + param_len]
                try:
                    value = value_bytes.decode('utf-8', errors='ignore').rstrip('\x00')
                except:
                    value = value_bytes
            
            params[key_name] = value
            
            if key_name in ['TITLE', 'TITLE_ID', 'CONTENT_ID', 'CATEGORY']:
                self.log(f"  {key_name}: {value}", "DEBUG")
        
        return params
    
    def _read_icon_from_entry(self, header: Dict[str, Any], entry: Dict[str, Any]) -> bytes:
        """Lê ícone da entry table principal"""
        # DataOffset JÁ é absoluto
        icon_offset = entry['data_offset']
        icon_size = entry['data_size']
        
        self.log(f"Icon offset: 0x{icon_offset:X}, size: {icon_size}", "DEBUG")
        
        icon_data = self.fetch_range(icon_offset, icon_offset + icon_size - 1)
        
        if icon_data[0:8] != b'\x89PNG\r\n\x1a\n':
            self.log("⚠ Ícone não é PNG válido", "DEBUG")
        
        return icon_data
    
    def _read_metas(self, header: Dict[str, Any], metas_entry: Dict[str, Any]) -> List[Dict[str, Any]]:
        """Lê seção METAS"""
        metas_offset = header['body_offset'] + metas_entry['data_offset']
        metas_size = metas_entry['data_size']
        
        metas_data = self.fetch_range(metas_offset, metas_offset + metas_size - 1)
        
        meta_count = struct.unpack('<I', metas_data[0:4])[0]
        self.log(f"METAS count: {meta_count}", "DEBUG")
        
        metas = []
        for i in range(meta_count):
            offset = 8 + (i * 32)
            meta_bytes = metas_data[offset:offset + 32]
            
            meta = {
                'id': struct.unpack('<I', meta_bytes[0x00:0x04])[0],
                'filename_offset': struct.unpack('<I', meta_bytes[0x04:0x08])[0],
                'data_offset': struct.unpack('<Q', meta_bytes[0x08:0x10])[0],
                'data_size': struct.unpack('<Q', meta_bytes[0x10:0x18])[0],
            }
            metas.append(meta)
        
        return metas
    
    def _read_param_sfo(self, param_sfo_meta: Dict[str, Any]) -> Dict[str, Any]:
        """Lê e parseia param.sfo (baseado em SFO.ParamSfo.FromStream)"""
        sfo_offset = param_sfo_meta['data_offset']
        sfo_size = param_sfo_meta['data_size']
        
        sfo_data = self.fetch_range(sfo_offset, sfo_offset + sfo_size - 1)
        
        # Validar magic
        if sfo_data[0:4] != b'\x00PSF':
            raise Exception(f"Invalid SFO magic")
        
        # Parse SFO header
        key_table_offset = struct.unpack('<I', sfo_data[8:12])[0]
        data_table_offset = struct.unpack('<I', sfo_data[12:16])[0]
        tables_entries = struct.unpack('<I', sfo_data[16:20])[0]
        
        self.log(f"SFO entries: {tables_entries}", "DEBUG")
        
        params = {}
        for i in range(tables_entries):
            entry_offset = 20 + (i * 16)
            entry_bytes = sfo_data[entry_offset:entry_offset + 16]
            
            key_offset = struct.unpack('<H', entry_bytes[0:2])[0]
            param_fmt = struct.unpack('<H', entry_bytes[2:4])[0]
            param_len = struct.unpack('<I', entry_bytes[4:8])[0]
            data_offset_rel = struct.unpack('<I', entry_bytes[12:16])[0]
            
            # Ler nome da chave
            key_start = key_table_offset + key_offset
            key_end = sfo_data.index(b'\x00', key_start)
            key_name = sfo_data[key_start:key_end].decode('ascii')
            
            # Ler valor
            value_start = data_table_offset + data_offset_rel
            
            if param_fmt == 0x0004:  # UTF-8 string
                value_end = sfo_data.index(b'\x00', value_start)
                value = sfo_data[value_start:value_end].decode('utf-8', errors='ignore')
            elif param_fmt == 0x0404:  # int32
                value = struct.unpack('<I', sfo_data[value_start:value_start + 4])[0]
            else:
                value = sfo_data[value_start:value_start + param_len]
            
            params[key_name] = value
        
        return params
    
    def _read_icon(self, icon_meta: Dict[str, Any]) -> bytes:
        """Lê ícone PNG"""
        icon_offset = icon_meta['data_offset']
        icon_size = icon_meta['data_size']
        
        icon_data = self.fetch_range(icon_offset, icon_offset + icon_size - 1)
        
        if icon_data[0:8] != b'\x89PNG\r\n\x1a\n':
            self.log("⚠ Ícone não é PNG válido", "DEBUG")
        
        return icon_data
    
    def _get_friendly_content_type(self, category: str) -> str:
        """Converte categoria para tipo amigável"""
        mapping = {
            'gd': 'Game Digital Application',
            'ac': 'Additional Content (DLC)',
            'gp': 'Game Application Patch',
            'gdo': 'PS2 Classic',
            'gc': 'Game Content',
            'bd': 'Blu-ray Disc',
        }
        return mapping.get(category.lower(), f'Unknown ({category})')
    
    def _get_bgft_package_type(self, category: str) -> str:
        """Converte categoria para tipo BGFT usado pelo PS4"""
        mapping = {
            'ac': 'PS4AC', 'bd': 'PS4BD', 'gc': 'PS4GC', 'gd': 'PS4GD',
            'gda': 'PS4GDA', 'gdc': 'PS4GDC', 'gdd': 'PS4GDD', 'gde': 'PS4GDE',
            'gdk': 'PS4GDK', 'gdl': 'PS4GDL', 'gdo': 'PS4GDO', 'gp': 'PS4GP',
            'gpc': 'PS4GPC', 'sd': 'PS4SD',
        }
        return mapping.get(category.lower(), 'PS4GD')


def main():
    parser = argparse.ArgumentParser(description='PKG Metadata Extractor - Baseado em LibOrbisPkg')
    parser.add_argument('--url', required=True, help='URL do arquivo PKG')
    parser.add_argument('--output', '-o', help='Salvar metadados em JSON')
    parser.add_argument('--save-icon', help='Salvar ícone PNG')
    parser.add_argument('--verbose', '-v', action='store_true', help='Modo verbose')
    
    args = parser.parse_args()
    
    print(f"\n{'=' * 60}\n  PKG Metadata Extractor\n{'=' * 60}\n")
    
    try:
        extractor = PKGMetadataExtractor(args.url, verbose=args.verbose)
        metadata = extractor.extract_metadata()
        
        # Preparar output
        output_metadata = {k: v for k, v in metadata.items() if k != 'icon_data'}
        output_metadata['has_icon'] = metadata.get('icon_data') is not None
        
        # Mostrar resultados
        print(f"\n{'=' * 60}\n  Metadados Extraídos\n{'=' * 60}\n")
        print(f"Titulo: {metadata.get('title', 'N/A')}")
        print(f"Content ID: {metadata['content_id']}")
        print(f"Title ID: {metadata.get('title_id', 'N/A')}")
        print(f"Categoria: {metadata.get('category', 'N/A')} ({metadata.get('content_type_friendly', 'N/A')})")
        print(f"Tipo BGFT: {metadata.get('bgft_package_type', 'N/A')}")
        print(f"Tamanho: {metadata['package_size']:,} bytes ({metadata['package_size'] / 1024 / 1024 / 1024:.2f} GB)")
        print(f"Digest: {metadata.get('header_digest', 'N/A')[:32]}...")
        
        if metadata.get('icon_data'):
            print(f"Icone: {len(metadata['icon_data']):,} bytes PNG")
        
        # System version
        if 'system_ver' in metadata.get('params', {}):
            sys_ver = metadata['params']['system_ver']
            if isinstance(sys_ver, int):
                major = (sys_ver >> 24) & 0xFF
                minor = (sys_ver >> 16) & 0xFF
                print(f"System Version: {major:02X}.{minor:02X}")
        
        # Salvar JSON
        if args.output:
            with open(args.output, 'w', encoding='utf-8') as f:
                json.dump(output_metadata, f, indent=2, ensure_ascii=False)
            print(f"\nMetadados salvos em: {args.output}")
        
        # Salvar ícone
        if args.save_icon and metadata.get('icon_data'):
            with open(args.save_icon, 'wb') as f:
                f.write(metadata['icon_data'])
            print(f"Icone salvo em: {args.save_icon}")
        
        print(f"\n{'=' * 60}\nExtracao concluida!\n{'=' * 60}\n")
        return 0
    except Exception as e:
        print(f"\n[ERROR] {e}")
        if args.verbose:
            import traceback
            traceback.print_exc()
        return 1


if __name__ == '__main__':
    sys.exit(main())
