# Splitter-py

Modulo para dividir qualquer arquivo em partes fixas de 1.9 GiB, gerar manifesto JSON com ranges e permitir merge futuro com concatenacao binaria crua (baixo uso de CPU).

## Como usar

### Split

```bash
python -m file_splitter split "C:\caminho\arquivo.bin"
```

Com hash por parte + hash final:

```bash
python -m file_splitter split "C:\caminho\arquivo.bin" --with-hash
```

### Merge

```bash
python -m file_splitter merge "C:\caminho\arquivo.bin.manifest.json" "C:\caminho\arquivo_restaurado.bin"
```

Com validacao de hash (se manifesto tiver hash):

```bash
python -m file_splitter merge "C:\caminho\arquivo.bin.manifest.json" "C:\caminho\arquivo_restaurado.bin" --verify-hash
```

### Validar manifesto e presenca das partes

```bash
python -m file_splitter validate "C:\caminho\arquivo.bin.manifest.json"
```

## Manifesto JSON Final

/<file-dir/<filename>.manifest.json
- `file_name`: nome do arquivo original
- `file_size`: tamanho total em bytes
- `chunk_size`: tamanho alvo de cada parte
- `parts[]`: lista ordenada das partes com:
  - `part`: indice sequencial
  - `file`: nome do arquivo da parte
  - `start`: byte inicial (inclusive)
  - `end`: byte final (inclusive)
  - `size`: tamanho da parte em bytes
  - `sha256` (opcional)


## notas de performance

- I/O em streaming com `buffer` (default 8 MiB)
- copia binaria direta (sem compressao/descompressao)
- merge por concatenacao em ordem do manifesto
- ranges inclusivos para reconstruir sem calculos complexos

Esse desenho permite merge com custo de CPU muito baixo, com foco no throughput de disco.
