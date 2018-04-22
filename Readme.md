# EncryEdu

Мы предлагаем суб-протокол на основе [EncryCore](https://github.com/EncryFoundation/EncryCore), который позволяет выстроить 
устойчивую образовательную инфраструктуру, которая позволяет:
* Заключать контракт на предоставление образовательных услуг
* Хранить в блокчейне EncryCore свидетельство о прохождении студентом 
  того или иного курса/образовательной программы, а также числовую характеристику его успеваемости в рамках курса 
  (например, оценку за экзамен). Студент при этом не имеет возможности самолично передать в чужое владение своё свидетельство.
* Расторгать/отзывать контракт или свидетельство о прохождении курса при участии стороны-арбитра.
Ядро протокола реализуется с помощью смарт-контрактов на [EncryScript](https://github.com/EncryFoundation/EncryScript)

Мы предполагаем взаимодействие 3-х типов участников сети:
1. Студент
2. ВУЗ
3. Министерство образования (арбитр)

## Описание протокола

### 1. Публикация образовательной программы
Образовательное учреждение выпускает по токену на каждое аудиторное место, объём эмиссии каждого токена равен 
максимальной числовой характеристике успеваемости студента принятой в ВУЗе (Например, 100 токенов, при применении 100-бальной шкалы оценки на экзамене.). Созданный актив, "закрывается" с помощью следующего скрипта:

    """
    Данный скрипт позволяет получить доступ к средствам, при условии:
    1. Транзакция, пытающаяся "разанлочить" средства подписана ровно 2-мя сторонами
    (необходимые публичные ключи перечистены ниже)
    """

    let universityPk = base58'7ouE517KpCuxa7TBZHEXXGVGhxZNZdBe7PsHt1KBq7UR'     # Публичный ключ ВУЗа
    let minobrPk = base58'11QPA7dQi6e1xzBUcTBg3R2eHz8txDSGFGk3PRMsujf'          # Публичный ключ Мин. Образования

    def validMultiSig(proof: Proof) -> Bool:
        match proof:
            case mulSig -> MultiSig:
                let sig1 = 1 if mulSig.proofs[0].isDefined && checkSig(mulSig.proofs[0].get.sigBytes, context.transaction.messageToSign, minobrPk) else 0
                let sig2 = 1 if mulSig.proofs[1].isDefined && checkSig(mulSig.proofs[1].get.sigBytes, context.transaction.messageToSign, universityPk) else 0
                return (sig1 + sig2) == 2
            case _:
                return false

    unlock if validMultiSig(context.proof)      # Для получения доступа к активу (Свидетельству о прохождении курса)
                                                # необходимы цифровые подписи ВУЗа и Мин образования.


### 2. Заключение договора об оказании образовательных услуг при помощи смарт-контракта EncryScript
Студент, желающий пройти ту или иную образовательную программу отправлят в сеть транзакцию с суммой, необходимой для
оплаты услуг образовательного учреждения. ВУЗу необходимо убедиться, что транзакция с оплатой попала в блокчейн. Актив, создаваемый данной транзакцией защищается следующим скриптом (контрактом):

    """
    Данный скрипт позволяет получить доступ к средствам, при условии:
    1. Транзакция, пытающаяся "разанлочить" средства подписана минимум 2-мя сторонами
    (необходимые публичные ключи перечистены ниже)
    2. Или, транзакция содержит "выход" с ожидаемым типом актива (`myAssetId`), предназначенным для студента.
    """

    let universityPk = base58'7ouE517KpCuxa7TBZHEXXGVGhxZNZdBe7PsHt1KBq7UR'     # Публичный ключ ВУЗа
    let minobrPk = base58'11QPA7dQi6e1xzBUcTBg3R2eHz8txDSGFGk3PRMsujf'          # Публичный ключ Мин. Образования
    let studentPk = base58'75Gs7HHUNnoEzsPgRRVABzQaC3UZVcayw9NY457Kx5p'         # Публичный ключ студента

    let myAssetId = base58'GtBn7qJwK1v1EbB6CZdgmkcvt849VKVfWoJBMEWsvTew'        # Id актива, предназначенного студенту,
                                                                                # его он узнаёт при записи на курс.
                                                                                # Именно этот актив студент должен получить
                                                                                # от ВУЗа при выпуске с курса.

    # Проверяем является ли `box` активом, подтверждающим факт прохождения курса студентом и его оценку.
    def isMyAsset(box: Box) -> Bool:
        match box:
            case asset -> AssetBox:
                return asset.tokenIdOpt.isDefined && asset.tokenIdOpt.get == myAssetId
            case _:
                return false

    # Валидируем пороговую подпись, необходимы подписи минимум 2-х сторон.
    def validThresholdSig(proof: Proof) -> Bool:
        match proof:
            case mulp -> MultiSig:
                let sig1 = 1 if mulp.proofs[0].isDefined && checkSig(mulp.proofs[0].get.sigBytes, context.transaction.messageToSign, minobrPk) else 0
                let sig2 = 1 if mulp.proofs[1].isDefined && checkSig(mulp.proofs[1].get.sigBytes, context.transaction.messageToSign, universityPk) else 0
                let sig3 = 1 if mulp.proofs[2].isDefined && checkSig(mulp.proofs[2].get.sigBytes, context.transaction.messageToSign, studentPk) else 0
                return (sig1 + sig2 + sig3) >= 2    # threshold sig 2 of 3
            case _:
                return false

    unlock if validThresholdSig(context.proof) || context.transaction.outputs.exists(isMyAsset)


### 3. Потребление образовательной услуги студентом (Происходит вне рамок протокола)
### 4. Выдача свидетельства о прохождениии студентом образовательной программы (aka диплома)
ВУЗ отправляет в сеть транзакцию содержащую в себе актив, являющийся репрезентацией "диплома" (ID этого 
актива студент указал в скрипте к оплате - `let myAssetId = base58'GtBn7qJwK1v1EbB6CZdgmkcvt849VKVfWoJBMEWsvTew'`).
Так как транзакция удовлетворяет условию (2) из скрипта, она имеет право присвоить оплату от студента.

Отрицательные сценарии:
### 5. Отзыв студентом оплаты за обучение в связи с тем, что ВУЗ не оказал образовательные услуги
Студент создаёт транзакцию, ссылающуюся на созданный им ранее актив, транзакция подписыватся ключом Мин. Образования (Арбитра)
и ключом студента, таким образом, данная транзакция удовлетворяет условию (1) скрипта, защищающего актив с оплатой. Студент получает
свою оплату обратно.
### 6. Отзыв диплома у студента
ВУЗ создаёт транзакцию, ссылающуюся на актив, репрезентующий диплом с оценкой, отправленный ранее студенту, транзакция подписыватся ключом Мин. Образования (Арбитра) и ключом ВУЗа, таким образом, данная транзакция удовлетворяет условию (1) скрипта, защищающего актив со свидетельством о прохождении студентом курса. Студент лишается свидетельства.
 

## Шаблоны запросов к API EncryCore

Отправка транзакции для выпуска токенов (см пункт "Публикация образовательной программы")

    [http://node_ip:8051/transactions/send]

    {
        "directives" : [{"scriptFingerprint" : "24N3HJx3q3D",          # Директива на создание нового типа актива
                         "typeId" : 5, 
                         "amount" : 100, 
                         "idx" : 0,
                         "script" : "11CmyAEN8DEHyDCvoxMUyE72eBWjkXGxxNhRCYSbk3c24m4FALZtHCiM2mcHjyQgvnF9kSTkJDyETvmkqiD5CW3M1",
                         "complexityScore" : 930}],
        "timestamp" : 1524400313742,
        "signature" : "hS5BnLbsA8T78gF574onfiU5dKnrjzAWFLsPTYtyaQCND4eMDmLTeuYQ5QPhcCNykdzRzMGscKWATJ1oTpW731fZrfhsu18ptqohPAQK7SifBMmgmxPuivWCtEaQm3n7RbKjuyFGrTxJaepWjmX5c3NqSgVQ6a3bY9BdGbcmzroNAF5NEv1zHSWY6bEizFsgjiqc7FcbGwwgFt9mKZXXj3sPZ2ejLwbqZj24WLvvTNLshesJsnCK7vYWygkjw2QfM3eCvQis1eisBmcT9YsTyn7W2mEdbyqZq2nLDAv4rVgQN5smgupN5gfYBqoqpgHtwUP3kTZqMo7Qx1zNotiuh7QnR5FTET8KNawRjxbKr2YzXEsYjEcxEWxoPYLwMr5c5a7QKxScjdbxBZv9hpAD3ZAoweTCx9ix4URY9Ln9pvCTXduabZUz2PeLaFJe8NvNJX3AzYDRZUDZ1bU4owC65A1FENF766Lei3zdBWTsZy6PQChjJ4eBtPDKChavgxE41yHDnaT7zPTBRi1Jw53a98M1DphLBxENdtfajmRZjVqqgJCfQ9fZUogoPCem64",
        "accountPubKey" : "4BYUDMQ6P65Wh28o57u5JLmwygHCgF9fuaMi7inzdDus",
        "id" : "3TFb24rb2v1pKDTVQig3ZGANGuCHXrLBGyy5c9rDLzzR",
        "unlockers" : [{"boxId" : "5nT6VN6DdWBhVByFKxt2HyJ43LNc7uepHvRXGanWp6q",
                        "proof" : "None"}],
        "fee" : 993
    }


Транзакция для получения оплаты от студента и выдачи свидетельства об образовании
(см пункт "Выдача свидетельства о прохождениии студентом образовательной программы (aka диплома)")

    [http://node_ip:8051/transactions/send]

    {
        # Директива на создание нового типа актива
        "directives" : [{"scriptFingerprint" : "24N3HJx3q3D",   # Первые 8 байт blake2b256Hash от сериализованного скрипта.
                         "typeId" : 5, 
                         "amount" : 100, 
                         "idx" : 0,
                         "script" : "111FxZHdod3vwkisK2PwNsgKPLUGurGkPZcGXAKz8RyMXBqXzW3ewh1FrZxzQKBV9FMoyGGYuxYWfVevud2CNQXGgLsk4ZdBDTB8SKFt4qQmWvtnZcxDjF3cL3TXfSU8XFb9f6pF7j74NRJ4cuMvok7pREBbMadzCMBmxcXLojLFyLiXyGsyDuuLQSYuz83JsMxPLJKvi58iXQ4Mo13VDUv4yR5dDp8TeAgCrCKMi439FYQwqfngrELHZyGXG8SdWNdbXq4AJW5MNJnRz4NHoZH2D76wyKbWN34muyaeGuTuMQdqjc2cbyU7YFHTAWvNBdHKseSWQMBCq1kLR6dmRsmLgrBfTJE2yX7ypJxMN41yxbUn6g5pimVePX6SkC8m7f2Ze4scM1Uv6bSpTpof6RZZ7hsoU69yaqjeREWGBvW9pUnfjVUxHiadH3qF6N1Q2hATyrjEuXiU1s7meBy4dTqDzPb8Utj8EwJGe2fG24tQLPSRiR9JoNB35fZG716XYpkdPfw53hFXLTxDbZJwUChJrppmRxhKv1xXkn5ovvGhTdAMrKhfsFEmvzEXj2TviHucGTGHzS8ZFdRZrTzGc68M38TZZBqkcwYCyYZHHnY7DFCTukUBn6YwtYtdde4ZQp7DZCbA8rsVzFXF4z1curNURQjV1FoKw5oGXuQsHbFLKPshSL4RDpPRcWDZakainNLuzNe5DnnUcmRhaZFQQtXCcskADanAtAVxusw8sYKFmy251DCKUUVqBNrTwY3drRvyBEPYAH5ovN1wbbxVMKAdd4GhgDomUDwaZkM8NBeNPURrTaxZ4EtS2sutjYW5TY4rBQGh9XbqnmLhDLKGyyRsm3tvyZPem2XTVkKshKbs7wMEKc9T141pfXsVQCPDY2trxsBd7s7XbEBgXBaRkaTdx7PXvhzSuV1QrqoiPnNA1h9XcVy8BTi4ypzyjVpFy1vVFasvswiUdoL2RqrHMdREF9AadPedujk9kgSRAFLM6aZsvgSoC2BV9b9gcgQJ2MV5PbxWxA2ZeRvwJ6fxJPQpXWKJzTKtKcFsWByBZ4hgnhr12pNu7yxkV1YUdk1ZiufjVq4qfKmjG6EiimTtmScFonDPBhq4zXWDzTDimVkKhRVD22j6tYTa2MWtNEvByrmxFmUGTHYukVGcdCTNFvKteQqP7ez1awFAW",
                         "complexityScore" : 930}],
        "timestamp" : 1524400313742,
        "signature" : "hS5BnLbsA8T78gF574onfiU5dKnrjzAWFLsPTYtyaQCND4eMDmLTeuYQ5QPhcCNykdzRzMGscKWATJ1oTpW731f",
        "accountPubKey" : "4BYUDMQ6P65Wh28o57u5JLmwygHCgF9fuaMi7inzdDus",
        "id" : "3TFb24rb2v1pKDTVQig3ZGANGuCHXrLBGyy5c9rDLzzR",
        # Ссылка на актив с оплатой от студента и пруф, необходимый для его "анлока", мульти-подпись, в данном случае.
        "unlockers" : [{"boxId" : "5nT6VN6DdWBhVByFKxt2HyJ43LNc7uepHvRXGanWp6q",
                        "proof" : {"proofs" : [{"typeId" : 1, 
                                   "signature" : "5EaoVcbeXoKbUN2bx8Nr1CLsYo7qhtZ6MdkUHeC9YE92rkUL8dsohZjLryiWiiiGiKtSXvqwvrxw1HaBhGkcE21H"},
                                   {"typeId" : 1, 
                                   "signature" : "Pb8Utj8EwJGe2fG24tQLPSRiR9JoNB35LsYo8qhtZ6MdkUHeC9YE12rkUL2dsohZjLryiWiiiGiKtSXvqwvrxw1"}]}}],
        "fee" : 993
    }


Запрос для получения "портфолио" пользователя, с целью отследить все его свидетельства об образовании:

    http://node_ip:8051/account/<student_address>/portfolio]    # Адрес студента из примера:
                                                                # 2xRvPN5CvDoHmnYtPTsccAtuAUMS9SBmMJ5RUn435EstH3PW18

## Запуск полной ноды EncryCore для теста протокола

Для запуска ноды необходимы следующие пакеты:
1. Java8
2. ScalaSDK
3. SBT

    $ git clone https://github.com/EncryFoundation/EncryCore.git

    $ cd EncryCore

    $ /bin/bash ./startup.sh

API ноды доступны на по адресу `http://127.0.0.1:9051`
