import collections
import os
import matplotlib.pyplot as plt
import numpy as np

class HashByteDistribution:
    """Analisa a distribuição dos valores de bytes em uma lista de hashes e plota gráfico."""
    def __init__(self, hash_list, outdir="resultados"):
        self.hash_list = hash_list
        self.byte_counts = collections.Counter()
        self.total_bytes = 0
        self.outdir = outdir
        self._analyze()

    def _analyze(self):
        for h in self.hash_list:
            self.byte_counts.update(h)
            self.total_bytes += len(h)

    def plot(self, title="Distribuição de valores de byte", filename="byte_dist.png"):
        os.makedirs(self.outdir, exist_ok=True)
        x = np.arange(256)
        y = np.array([self.byte_counts[b] for b in range(256)])
        plt.figure(figsize=(12,5))
        plt.bar(x, y, color='royalblue')
        plt.title(title)
        plt.xlabel('Valor do Byte (0-255)')
        plt.ylabel('Frequência')
        plt.tight_layout()
        plt.savefig(os.path.join(self.outdir, filename))
        plt.close()

class HashBitDistribution:
    """Analisa a distribuição de bits 0/1 em uma lista de hashes e plota gráfico."""
    def __init__(self, hash_list, outdir="resultados"):
        self.hash_list = hash_list
        self.bit_counts = [0] * (len(hash_list[0]) * 8)
        self.total_hashes = len(hash_list)
        self.bits_per_hash = len(hash_list[0]) * 8
        self.outdir = outdir
        self._analyze()

    def _analyze(self):
        for h in self.hash_list:
            for i in range(self.bits_per_hash):
                if (h[i//8] >> (7-(i%8))) & 1:
                    self.bit_counts[i] += 1

    def plot(self, title="Distribuição de bits 1 por posição", filename="bit_dist.png"):
        os.makedirs(self.outdir, exist_ok=True)
        x = np.arange(self.bits_per_hash)
        y = np.array([count / self.total_hashes for count in self.bit_counts])
        plt.figure(figsize=(12,5))
        plt.bar(x, y, color='darkorange')
        plt.title(title)
        plt.xlabel('Posição do Bit')
        plt.ylabel('Fração de bits 1')
        plt.ylim(0,1)
        plt.tight_layout()
        plt.savefig(os.path.join(self.outdir, filename))
        plt.close()

class AvalancheEffectTest:
    """Testa o efeito avalanche: quantos bits mudam ao alterar 1 bit da mensagem e plota histograma."""
    def __init__(self, hash_func, msg_len, n_tests=100, outdir="resultados"):
        import random
        self.hash_func = hash_func
        self.msg_len = msg_len
        self.n_tests = n_tests
        self.results = []
        self.bits = None
        self.outdir = outdir
        self._run()

    def _run(self):
        import random
        for _ in range(self.n_tests):
            msg = bytes(random.getrandbits(8) for _ in range(self.msg_len))
            msg2 = bytearray(msg)
            bit_idx = random.randint(0, self.msg_len*8-1)
            byte_idx, bit_in_byte = divmod(bit_idx, 8)
            msg2[byte_idx] ^= (1 << bit_in_byte)
            h1 = self.hash_func(msg)
            h2 = self.hash_func(bytes(msg2))
            if self.bits is None:
                self.bits = len(h1) * 8
            diff = sum(bin(b1 ^ b2).count('1') for b1, b2 in zip(h1, h2))
            self.results.append(diff)

    def plot(self, title="Efeito Avalanche - Histograma", filename="avalanche_hist.png"):
        os.makedirs(self.outdir, exist_ok=True)
        plt.figure(figsize=(8,5))
        plt.hist(self.results, bins=range(min(self.results), max(self.results)+2), color='seagreen', rwidth=0.8)
        plt.title(title)
        plt.xlabel('Bits diferentes')
        plt.ylabel('Frequência')
        plt.tight_layout()
        plt.savefig(os.path.join(self.outdir, filename))
        plt.close()

class ByteDistributionAnalysis:
    """Classe para análise e plotagem da distribuição de bytes em hashes."""
    def __init__(self, list_of_hashes, outdir="resultados", filename="byte_dist_custom.png"):
        import collections
        self.list_of_hashes = list_of_hashes
        self.outdir = outdir
        self.filename = filename
        self.all_bytes = bytearray()
        for h_bytes in list_of_hashes:
            self.all_bytes.extend(h_bytes)
        self.counts = collections.Counter(self.all_bytes)
        self.labels, self.values = zip(*sorted(self.counts.items())) if self.counts else ([],[])

    def plot(self):
        import os
        import matplotlib.pyplot as plt
        if not self.all_bytes:
            print("Nenhum byte para analisar.")
            return
        os.makedirs(self.outdir, exist_ok=True)
        plt.figure(figsize=(15, 6))
        plt.bar(self.labels, self.values)
        plt.xlabel("Valor do Byte (0-255)")
        plt.ylabel("Frequência")
        plt.title("Distribuição de Valores de Byte na Saída do Hash")
        plt.xticks(range(0, 256, 16))
        plt.grid(True, axis='y', linestyle='--')
        plt.tight_layout()
        plt.savefig(os.path.join(self.outdir, self.filename))
        plt.close()
        expected_count = len(self.all_bytes) / 256.0
        print(f"\nTotal de bytes analisados: {len(self.all_bytes)}")
        print(f"Contagem esperada por valor de byte (se uniforme): {expected_count:.2f}")

class BitDistributionAnalysis:
    """Classe para análise e plotagem da proporção de bits 0 e 1 em um bitstream."""
    def __init__(self, bit_stream, outdir="resultados", filename="bit_zeros_uns.png"):
        self.bit_stream = bit_stream
        self.outdir = outdir
        self.filename = filename
        self.num_zeros = bit_stream.count('0')
        self.num_ones = bit_stream.count('1')
        self.total_bits = len(bit_stream)

    def plot(self):
        import os
        import matplotlib.pyplot as plt
        if not self.bit_stream:
            print("Nenhum bit para analisar.")
            return
        os.makedirs(self.outdir, exist_ok=True)
        plt.figure(figsize=(5,4))
        plt.bar(['Zeros', 'Uns'], [self.num_zeros, self.num_ones], color=['#1f77b4', '#ff7f0e'])
        plt.title("Proporção de bits 0 e 1")
        plt.ylabel("Quantidade")
        plt.tight_layout()
        plt.savefig(os.path.join(self.outdir, self.filename))
        plt.close()
        print(f"\nAnálise de Distribuição de Bits:")
        print(f"Total de bits: {self.total_bits}")
        print(f"Número de Zeros: {self.num_zeros} ({(self.num_zeros/self.total_bits)*100:.2f}%)")
        print(f"Número de Uns  : {self.num_ones} ({(self.num_ones/self.total_bits)*100:.2f}%)")

def generate_hash_bitstream(lwhash_instance, num_hashes=1000, message_prefix=b"test_sequence_"):
    """
    Gera uma longa string de bits concatenando múltiplos hashes.
    """
    all_hash_bytes = bytearray()
    from utils import string_to_bytes
    for i in range(num_hashes):
        message = message_prefix + string_to_bytes(str(i))
        h_bytes = lwhash_instance.compute_hash(message)
        all_hash_bytes.extend(h_bytes)
    bit_stream = "".join(format(byte, '08b') for byte in all_hash_bytes)
    return bit_stream


def generate_list_of_hashes(lwhash_instance, num_hashes=1000, message_prefix=b"test_sequence_"):
    """
    Gera uma lista de hashes (como objetos bytes).
    """
    from utils import string_to_bytes
    hashes_list = []
    for i in range(num_hashes):
        message = message_prefix + string_to_bytes(str(i))
        h_bytes = lwhash_instance.compute_hash(message)
        hashes_list.append(h_bytes)
    return hashes_list
