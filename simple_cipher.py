import math
import random
import string


class SimpleCipher:
    """ Шифр простой замены """

    def __init__(self):
        """
        self.alphabet -
        self.alphabet_map -
        self.map -
        self.map_inv -
        """
        self.alphabet = " " + string.ascii_lowercase
        self.module = len(string.ascii_lowercase)
        self.alphabet_map = self.__get_alphabet_map()
        self.map = [
            17, 26, 9, 22, 20, 11, 2, 23, 18, 5, 21, 3, 24, 16, 19, 0, 15, 10, 6, 7, 8, 12, 4, 13, 14, 1, 25
        ]
        self.map_inv = [
            15, 25, 6, 11, 22, 9, 18, 19, 20, 2, 17, 5, 21, 23, 24, 16, 13, 0, 8, 14, 4, 10, 3, 7, 12, 26, 1
        ]

    def __get_alphabet_map(self):
        alphabet = {}
        for num, letter in enumerate(self.alphabet):
            alphabet[letter] = num

        return alphabet

    def _get_index_by_letter(self, letter: str):
        """
        Возвращает индекс буквы из массива alphabet
        Если введена не буква или такой буквы нет в алфавите
        то возвращает исключение
        :param letter:
        :return:
        """
        if len(letter) != 1:
            raise ValueError('Функция __get_index_by_letter принимает 1 букву в качестве аргумента')
        else:
            letter = letter.lower()

        index = self.alphabet_map.get(letter)
        if index is None:
            raise ValueError('Нет такой буквы в переменной alphabet')
        return index

    def _get_letter_by_index(self, index):
        """
        Возвращает букву по индексу в алфавите
        :param index:
        :return:
        """
        return self.alphabet[index]

    def encrypt(self, message: str):
        encrypted_message = []

        for i in message:
            index = self._get_index_by_letter(i)
            enc_index = self.map[index]
            encrypted_message.append(self._get_letter_by_index(enc_index))

        return ''.join(encrypted_message)

    def decrypt(self, encrypted_message: str):
        decrypted_message = []

        for i in encrypted_message:
            enc_index = self._get_index_by_letter(i)
            decr_index = self.map_inv[enc_index]
            decrypted_message.append(self._get_letter_by_index(decr_index))

        return ''.join(decrypted_message)


class AffineCipher(SimpleCipher):
    """ Аффинный шифр """

    def __init__(self):
        super().__init__()
        self._secret_key = self._get_secret_key()

    def _get_secret_key(self):
        """
        Генератор ключа афинного шифра.
        m - модуль алгоритма (мощность алфавита шифрования)
        а - должен быть взаимнопростым с модулем шифрования
        b - произвольное число (в пределах модуля алгоритма)
        :return: (a, b, m)
        """
        a = random.randrange(1, 100) % self.module

        if a < 3 or math.gcd(a, self.module) != 1:
            a = random.randrange(1, 100) % self.module

        b = random.randrange(1, 100) % self.module
        return a, b

    def encrypt(self, message: str):
        """
        Производит преобразования аффинного шифра:
        y = (ax + b) % m
        :param message: str - Открытый текст для зашифрования
        :return: encrypted_message: str - Зашифрованный текст
        """
        encrypted_message = []

        for i in message:
            index = self._get_index_by_letter(i)
            enc_index = (self._secret_key[0] * index + self._secret_key[1]) % self.module
            encrypted_message.append(self._get_letter_by_index(enc_index))

        return ''.join(encrypted_message)

    def decrypt(self, encrypted_message: str):
        """
        Производит преобразования расшифрования аффинного шифра
        x = ((y - b) * a_inv) % m
        :param encrypted_message: str - Строка с зашифрованным текстом
        :return: decrypted_message: str - Строка с расшифрованным текстом
        """
        decrypted_message = []

        for i in encrypted_message:
            index = self._get_index_by_letter(i)
            a_inv = pow(self._secret_key[0], -1, self.module)
            dec_index = ((index - self._secret_key[1]) * a_inv) % self.module
            decrypted_message.append(self._get_letter_by_index(dec_index))

        return ''.join(decrypted_message)


class AffineRecurrentCipher(AffineCipher):
    """ Аффинный рекуррентный шифр """

    def __init__(self):
        super().__init__()
        self.__secret_key = self._get_secret_key()

    def _override_key(self, secret_keys):
        """ Пересчитываем ключ шифрования """
        a = (secret_keys[-1][0] * secret_keys[-2][0]) % self.module
        b = (secret_keys[-1][1] + secret_keys[-2][1]) % self.module
        return a, b

    def encrypt(self, message: str):
        secret_keys = [self.__secret_key, self.__secret_key]
        encrypted_message = []

        for num, i in enumerate(message):
            if num > 1:
                # Пересчитываем ключ шифрования и добавляем в массив
                a, b = self._override_key(secret_keys)
                secret_keys.append((a, b))
            else:
                a, b, m = secret_keys[num]

            # Шифруем очередной симвом открытого текста
            index = self._get_index_by_letter(i)
            enc_index = (a * index + b) % self.module
            encrypted_message.append(self._get_letter_by_index(enc_index))

        return ''.join(encrypted_message)

    def decrypt(self, encrypted_message: str):
        secret_keys = [self.__secret_key, self.__secret_key]
        decrypted_message = []

        for num, i in enumerate(encrypted_message):
            if num > 1:
                # Пересчитываем ключ шифрования и добавляем в массив
                a, b = self._override_key(secret_keys)
                secret_keys.append((a, b))
            else:
                a, b = secret_keys[num]

            # Расшифровываем очередной симвом
            index = self._get_index_by_letter(i)
            a_inv = pow(a, -1, self.module)
            decr_index = (index - b) * a_inv % self.module
            decrypted_message.append(self._get_letter_by_index(decr_index))

        return ''.join(decrypted_message)
