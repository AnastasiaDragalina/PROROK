#!/bin/bash
#
# description: Оболочка для импорта данных в БД ПодХОД 
#
# author: Sergey Novikov 
#

###########################################
# Коды возвращаемых значений: 
# 0 - нет ошибок 
# 1 - отсутствует odsInterface 
# 2 - отсутствует соединение с базой 
# 3 - ошибка открытия файла 
# 4 - ошибка сохранения файла 
# 5 - ошибка чтения файла 
# 6 - ошибка очистки БД 
# 7 - неверно указаны параметры вызова 
###########################################

#############################
#   Глобальные переменные   #
#############################

BINARY_PATH=/usr/local/ods/bin/ods_meta_import
LOG_MODE="/dev/null"
CONFIG_PATH=./config_import.xml
XML_PATH=./meta.xml
RESULT=
#############################

echo "Импорт данных в БД ПодХОД..."

if [ ! -z $1 ]; then
    XML_PATH=$1
fi

TEMP=which $BINARY_PATH
WH=$?
if [[ "$WH" -eq 1 ]]
then 
    echo "Не найден исполняемый файл"
    exit 1
fi

if [[ ! -f "$CONFIG_PATH" ]]
then 
    echo "Не найден конфигурационный файл"
    exit 1
fi

if (! test -f "$XML_PATH" )
then 
    echo "Не найден файл для импорта"
    exit 1
fi

#"$BINARY_PATH" "$CONFIG_PATH" "$XML_PATH" &> "$LOG_MODE"
"$BINARY_PATH" "$CONFIG_PATH" "$XML_PATH"
RESULT="$?"

if [[ "$RESULT" -eq 0 ]] 
then 
    echo "Импорт данных успешно завершён"
    exit 0
fi 

if [[ "$RESULT" -eq 1 ]]
then
    echo "Отсутствует ODS Interface"
    exit 1
fi

if [[ "$RESULT" -eq 2 ]]
then
    echo "Отсутствует соединение с БД"
    exit 1
fi

if [[ "$RESULT" -eq 3 ]]
then
    echo "Ошибка открытия файла с данными БД"
    exit 1
fi

if [[ "$RESULT" -eq 5 ]]
then
    echo "Ошибка чтения файла с данными БД"
    exit 1
fi

if [[ "$RESULT" -eq 7 ]]
then
    echo "Неверно указаны параметры вызова"
    exit 1
fi

echo "Ошибка $RESULT"
exit 1