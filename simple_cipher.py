import math
import random
import string


class SimpleCipher:
    """ Шифр простой замены """

    def __init__(self, mapping=None):
        """
        self.alphabet - Используемый алфавит (ascii + пробел)
        self.alphabet_map - Таблица соответствия идекса и букв алфавита
        self.secret_key - Ключ шифрования - таблица замены. Если Таблица
        замены не задана то используется таблица замены по-умолчанию.
        """
        self.alphabet = string.ascii_lowercase + string.ascii_uppercase + string.digits + string.punctuation + " "
        self.module = len(self.alphabet)
        self.alphabet_map = self.__get_alphabet_map()
        self.secret_key = self.__get_mapping(mapping)

    @staticmethod
    def __get_mapping(mapping):
        if mapping is None:
            mapping = [
                [29, 44, 65, 31, 48, 4, 92, 84, 10, 37, 90, 9, 66, 93, 25, 17, 47, 35, 33, 20, 23, 19, 63, 30, 24, 75,
                 68, 27, 1, 62, 59, 76, 7, 50, 16, 0, 5, 26, 22, 8, 85, 80, 54, 74, 89, 39, 36, 57, 55, 18, 40, 69, 43,
                 28, 86, 71, 91, 6, 78, 87, 12, 41, 15, 34, 56, 70, 58, 52, 21, 2, 60, 82, 67, 45, 49, 53, 11, 88, 73,
                 13, 79, 42, 46, 64, 61, 38, 94, 77, 83, 72, 14, 81, 51, 32, 3],
                [35, 28, 69, 94, 5, 36, 57, 32, 39, 11, 8, 76, 60, 79, 90, 62, 34, 15, 49, 21, 19, 68, 38, 20, 24, 14,
                 37, 27, 53, 0, 23, 3, 93, 18, 63, 17, 46, 9, 85, 45, 50, 61, 81, 52, 1, 73, 82, 16, 4, 74, 33, 92, 67,
                 75, 42, 48, 64, 47, 66, 30, 70, 84, 29, 22, 83, 2, 12, 72, 26, 51, 65, 55, 89, 78, 43, 25, 31, 87, 58,
                 80, 41, 91, 71, 88, 7, 40, 54, 59, 77, 44, 10, 56, 6, 13, 86]
            ]
        return mapping

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
        return self.alphabet_map.get(letter)

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
            enc_index = self.secret_key[0][index]
            encrypted_message.append(self._get_letter_by_index(enc_index))

        return ''.join(encrypted_message)

    def decrypt(self, encrypted_message: str):
        decrypted_message = []

        for i in encrypted_message:
            enc_index = self._get_index_by_letter(i)
            decr_index = self.secret_key[1][enc_index]
            decrypted_message.append(self._get_letter_by_index(decr_index))

        return ''.join(decrypted_message)


class AffineCipher(SimpleCipher):
    """ Аффинный шифр """

    def __init__(self, secret_key=None):
        super().__init__()
        self.secret_key = self._get_secret_key(secret_key)

    def _get_secret_key(self, secret_key):
        """
        Генератор ключа афинного шифра.
        m - модуль алгоритма (мощность алфавита шифрования)
        а - должен быть взаимнопростым с модулем шифрования
        b - произвольное число (в пределах модуля алгоритма)
        :return: (a, b)
        """
        if secret_key is None:
            a = random.randrange(1, 100) % self.module

            if a < 3 or math.gcd(a, self.module) != 1:
                a = random.randrange(1, 100) % self.module

            b = random.randrange(1, 100) % self.module
        else:
            a, b = secret_key

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
            enc_index = (self.secret_key[0] * index + self.secret_key[1]) % self.module
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
            a_inv = pow(self.secret_key[0], -1, self.module)
            dec_index = ((index - self.secret_key[1]) * a_inv) % self.module
            decrypted_message.append(self._get_letter_by_index(dec_index))

        return ''.join(decrypted_message)


class AffineRecurrentCipher(AffineCipher):
    """ Аффинный рекуррентный шифр """

    def __init__(self, secret_key=None, secret_key_2=None):
        super().__init__()
        self.secret_keys = [
            self._get_secret_key(secret_key),
            self._get_secret_key(secret_key_2)
        ]

    def _override_key(self, secret_keys):
        """ Пересчитываем ключ шифрования """
        a = (secret_keys[-1][0] * secret_keys[-2][0]) % self.module
        b = (secret_keys[-1][1] + secret_keys[-2][1]) % self.module
        return a, b

    def encrypt(self, message: str):
        secret_keys = [self.secret_keys[0], self.secret_keys[1]]
        encrypted_message = []

        for num, i in enumerate(message):
            if num > 1:
                # Пересчитываем ключ шифрования и добавляем в массив
                a, b = self._override_key(secret_keys)
                secret_keys.append((a, b))
            else:
                a, b = secret_keys[num]

            # Шифруем очередной симвом открытого текста
            index = self._get_index_by_letter(i)
            enc_index = (a * index + b) % self.module
            encrypted_message.append(self._get_letter_by_index(enc_index))

        return ''.join(encrypted_message)

    def decrypt(self, encrypted_message: str):
        secret_keys = [self.secret_keys[0], self.secret_keys[1]]
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
