# Тестовое

задача
доказать меркл-пруф с публичными  инпутами, модифицировав ./src/...

приватные инпуты [[private_input]]

- msg (bytes) 
- msg_hash
- merkle_root
- merkle_branch от msg_hash к merkle_root

публичным инпутом является public_input = hash(msg_hash & root_hash)

вторым публичным инпутом является check_result: true - результат того, что функция проверки меркл-пруфа дала положительный результат

 пруф должен проверять 
 public_input == hash(msg_hash & root_hash)
 (merkle_root(msg, branch) = root_hash) ==  check_result

Чтобы проверять результат, сейчас нужно использовать специальный assert __builtin_assigner_exit_check, вот пример в тестах:
https://github.com/NilFoundation/zkLLVM/blob/master/tests/cpp/algebra/bool/assigner_exit_check.cpp#L15

он не даст сгенерить пруф если неверные инпуты

для всего использовать криптографию из crypto3 конечно

см README.md


результатом по идее должен быть положительный результат ончейн верификации при верных данных и негативный результат при неверных, в хх тесты и деплой есть


суть - сжатое доказательство того что у нас были верные данные и мы произвели вычисление которое это доказывает

