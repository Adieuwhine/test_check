#!/bin/bash
# Глобальный сканер для файлов с диапазонами IP

echo "🌍 Глобальный сканер диапазонов IP (первые 200 адресов в подсети)"
echo "=========================================="

# Директория с файлами стран
COUNTRIES_DIR="./countries"
RESULTS_DIR="./scan_results"
mkdir -p "$RESULTS_DIR"

# Количество потоков для параллельного сканирования
THREADS=50
TIMEOUT=2
MAX_IPS_PER_SUBNET=400  # Максимальное количество IP для сканирования в каждой подсети
OPERATOR="Т2"  # Оператор, на котором проводится проверка

# Файл белого списка
WHITELIST_FILE="${RESULTS_DIR}/cidrwhitelist.txt"

# Функция для конвертации IP в число
ip_to_int() {
    local ip=$1
    local a b c d
    IFS=. read -r a b c d <<< "$ip"
    echo $((a * 256 ** 3 + b * 256 ** 2 + c * 256 + d))
}

# Функция для конвертации числа в IP
int_to_ip() {
    local ip_int=$1
    echo "$((ip_int >> 24 & 255)).$((ip_int >> 16 & 255)).$((ip_int >> 8 & 255)).$((ip_int & 255))"
}

# Функция для проверки одного IP
check_single_ip() {
    local ip=$1
    local country=$2
    
    # Проверяем ping
    if ping -c 1 -W "$TIMEOUT" "$ip" &>/dev/null; then
        echo "✅ $ip - доступен (ping)" >> "${RESULTS_DIR}/${country}_active.txt"
        return 0
    fi
    
    return 1
}

# Функция для проверки доступности подсети (проверяет несколько IP)
check_subnet_availability() {
    local range=$1
    local country_name=$2
    local start_ip end_ip start_int end_int
    
    # Определяем формат диапазона
    if [[ "$range" == *"/"* ]]; then
        local network=$(echo "$range" | cut -d'/' -f1)
        local prefix=$(echo "$range" | cut -d'/' -f2)
        local mask=$((0xffffffff << (32 - prefix) & 0xffffffff))
        
        start_int=$(ip_to_int "$network")
        start_int=$((start_int & mask))
        end_int=$((start_int | ~mask & 0xffffffff))
    else
        start_ip=$(echo "$range" | cut -d'-' -f1)
        end_ip=$(echo "$range" | cut -d'-' -f2)
        start_int=$(ip_to_int "$start_ip")
        end_int=$(ip_to_int "$end_ip")
    fi
    
    local total_ips=$((end_int - start_int + 1))
    local ips_to_check=$((total_ips < 5 ? total_ips : 5))  # Проверяем до 5 IP для определения доступности подсети
    
    local available_count=0
    local checked_count=0
    
    # Проверяем несколько IP из подсети
    for ((i = 0; i < ips_to_check; i++)); do
        local test_ip_int=$((start_int + i * (total_ips / ips_to_check)))
        local test_ip=$(int_to_ip "$test_ip_int")
        
        if ping -c 1 -W "$TIMEOUT" "$test_ip" &>/dev/null; then
            ((available_count++))
        fi
        ((checked_count++))
    done
    
    # Если хотя бы один IP доступен, считаем подсеть доступной
    if [ "$available_count" -gt 0 ]; then
        # Добавляем в белый список
        if [[ "$range" == *"/"* ]]; then
            echo "$range $country_name - $OPERATOR" >> "$WHITELIST_FILE"
        else
            # Конвертируем диапазон в CIDR (упрощенная версия)
            local prefix_size=32
            local range_size=$((end_int - start_int + 1))
            
            # Определяем примерный префикс по размеру диапазона
            case $range_size in
                256) prefix_size=24 ;;
                512) prefix_size=23 ;;
                1024) prefix_size=22 ;;
                2048) prefix_size=21 ;;
                4096) prefix_size=20 ;;
                8192) prefix_size=19 ;;
                16384) prefix_size=18 ;;
                32768) prefix_size=17 ;;
                65536) prefix_size=16 ;;
                *) prefix_size=24 ;; # По умолчанию /24
            esac
            
            local cidr_network=$(int_to_ip "$start_int")
            echo "${cidr_network}/${prefix_size} $country_name - $OPERATOR" >> "$WHITELIST_FILE"
        fi
        return 0
    fi
    
    return 1
}

# Функция для обработки одного диапазона (только первые 200 IP)
process_range_limited() {
    local range=$1
    local country=$2
    local start_ip end_ip start_int end_int
    
    # Определяем формат: CIDR или диапазон
    if [[ "$range" == *"/"* ]]; then
        # CIDR формат: 192.168.1.0/24
        local network=$(echo "$range" | cut -d'/' -f1)
        local prefix=$(echo "$range" | cut -d'/' -f2)
        
        # Вычисляем маску
        local mask=$((0xffffffff << (32 - prefix) & 0xffffffff))
        
        # Вычисляем начальный и конечный IP
        start_int=$(ip_to_int "$network")
        start_int=$((start_int & mask))
        end_int=$((start_int | ~mask & 0xffffffff))
        
        start_ip=$(int_to_ip "$start_int")
        end_ip=$(int_to_ip "$end_int")
        
    elif [[ "$range" == *"-"* ]]; then
        # Диапазон формат: 192.168.1.0-192.168.1.255
        start_ip=$(echo "$range" | cut -d'-' -f1)
        end_ip=$(echo "$range" | cut -d'-' -f2)
        
        start_int=$(ip_to_int "$start_ip")
        end_int=$(ip_to_int "$end_ip")
    else
        echo "❌ Неверный формат диапазона: $range"
        return 1
    fi
    
    local total_ips_in_range=$((end_int - start_int + 1))
    local ips_to_scan=$((total_ips_in_range < MAX_IPS_PER_SUBNET ? total_ips_in_range : MAX_IPS_PER_SUBNET))
    
    echo "🔍 Сканируем диапазон: $range (первые $ips_to_scan IP из $total_ips_in_range)"
    
    # Сначала проверяем доступность подсети для белого списка
    check_subnet_availability "$range" "$country"
    
    # Сканируем только первые MAX_IPS_PER_SUBNET IP в диапазоне
    local scanned_count=0
    for ((ip_int = start_int; ip_int <= end_int && scanned_count < MAX_IPS_PER_SUBNET; ip_int++)); do
        current_ip=$(int_to_ip "$ip_int")
        
        # Проверяем IP
        check_single_ip "$current_ip" "$country" &
        ((scanned_count++))
        
        # Ограничиваем количество параллельных процессов
        while [ $(jobs -r | wc -l) -ge "$THREADS" ]; do
            sleep 0.1
        done
    done
    
    # Ждем завершения всех процессов
    wait
}

# Функция для обработки файла страны
process_country_file() {
    local country_file=$1
    local country_name=$(basename "$country_file" .txt)
    
    echo ""
    echo "🎯 Обрабатываем страну: $country_name"
    echo "=========================================="
    
    # Очищаем предыдущие результаты
    > "${RESULTS_DIR}/${country_name}_active.txt"
    > "${RESULTS_DIR}/${country_name}_summary.txt"
    
    local total_ranges=0
    local total_ips=0
    local total_ips_to_scan=0
    local available_subnets=0
    
    # Читаем файл построчно
    while IFS= read -r range; do
        # Пропускаем пустые строки и комментарии
        [[ -z "$range" || "$range" =~ ^# ]] && continue
        
        ((total_ranges++))
        
        # Определяем общее количество IP в диапазоне
        if [[ "$range" == *"/"* ]]; then
            local prefix=$(echo "$range" | cut -d'/' -f2)
            local range_size=$((2 ** (32 - prefix)))
        else
            local start_ip=$(echo "$range" | cut -d'-' -f1)
            local end_ip=$(echo "$range" | cut -d'-' -f2)
            local start_int=$(ip_to_int "$start_ip")
            local end_int=$(ip_to_int "$end_ip")
            local range_size=$((end_int - start_int + 1))
        fi
        
        total_ips=$((total_ips + range_size))
        
        # Определяем сколько IP будем сканировать (не более MAX_IPS_PER_SUBNET)
        local ips_in_this_range=$((range_size < MAX_IPS_PER_SUBNET ? range_size : MAX_IPS_PER_SUBNET))
        total_ips_to_scan=$((total_ips_to_scan + ips_in_this_range))
        
        # Обрабатываем диапазон (только первые 200 IP)
        process_range_limited "$range" "$country_name"
        
        # Проверяем, добавлена ли подсеть в белый список
        if grep -q "$range" "$WHITELIST_FILE" 2>/dev/null; then
            ((available_subnets++))
        fi
        
    done < "$country_file"
    
    # Создаем суммарный отчет
    active_count=$(wc -l < "${RESULTS_DIR}/${country_name}_active.txt" 2>/dev/null || echo 0)
    
    echo "📊 $country_name - ИТОГО:" | tee -a "${RESULTS_DIR}/${country_name}_summary.txt"
    echo "   Диапазонов: $total_ranges" | tee -a "${RESULTS_DIR}/${country_name}_summary.txt"
    echo "   Доступных подсетей: $available_subnets" | tee -a "${RESULTS_DIR}/${country_name}_summary.txt"
    echo "   Всего IP в подсетях: $total_ips" | tee -a "${RESULTS_DIR}/${country_name}_summary.txt"
    echo "   IP отсканировано: $total_ips_to_scan" | tee -a "${RESULTS_DIR}/${country_name}_summary.txt"
    echo "   Активных IP: $active_count" | tee -a "${RESULTS_DIR}/${country_name}_summary.txt"
    
    if [ "$total_ips_to_scan" -gt 0 ]; then
        echo "   Процент доступности: $((active_count * 100 / total_ips_to_scan))%" | tee -a "${RESULTS_DIR}/${country_name}_summary.txt"
    fi
    
    if [ "$active_count" -gt 0 ]; then
        echo "   Активные IP сохранены в: ${RESULTS_DIR}/${country_name}_active.txt" | tee -a "${RESULTS_DIR}/${country_name}_summary.txt"
    fi
}

# Функция для создания финального белого списка
create_final_whitelist() {
    echo ""
    echo "📋 СОЗДАНИЕ ФАЙЛА БЕЛОГО СПИСКА"
    echo "=========================================="
    
    # Сортируем и удаляем дубликаты
    if [ -f "$WHITELIST_FILE" ]; then
        sort -u "$WHITELIST_FILE" -o "${RESULTS_DIR}/cidrwhitelist_sorted.txt"
        
        echo "Формат: CIDR + название + оператор" | tee "${RESULTS_DIR}/cidrwhitelist_final.txt"
        echo "==========================================" | tee -a "${RESULTS_DIR}/cidrwhitelist_final.txt"
        cat "${RESULTS_DIR}/cidrwhitelist_sorted.txt" | tee -a "${RESULTS_DIR}/cidrwhitelist_final.txt"
        
        local whitelist_count=$(wc -l < "${RESULTS_DIR}/cidrwhitelist_sorted.txt")
        echo ""
        echo "✅ Белый список создан: ${RESULTS_DIR}/cidrwhitelist_final.txt"
        echo "   Доступных подсетей: $whitelist_count"
        
        # Показываем примеры из белого списка
        echo ""
        echo "📄 Примеры из белого списка:"
        head -5 "${RESULTS_DIR}/cidrwhitelist_final.txt" | while read line; do
            echo "   📍 $line"
        done
        
        if [ "$whitelist_count" -gt 5 ]; then
            echo "   ... и еще $((whitelist_count - 5)) подсетей"
        fi
    else
        echo "❌ Файл белого списка не создан"
    fi
}

# Главная функция
main() {
    echo "🌍 Глобальный сканер IP диапазонов"
    echo "Сканирует первые $MAX_IPS_PER_SUBNET адресов в каждой подсети"
    echo "Оператор проверки: $OPERATOR"
    echo "Ищет файлы в директории: $COUNTRIES_DIR"
    echo "Результаты в: $RESULTS_DIR"
    echo "=========================================="
    
    # Очищаем файл белого списка
    > "$WHITELIST_FILE"
    
    # Проверяем существование директории
    if [ ! -d "$COUNTRIES_DIR" ]; then
        echo "❌ Директория $COUNTRIES_DIR не существует!"
        echo "Создайте директорию и поместите туда файлы стран:"
        echo "  Russia.txt, Kazakhstan.txt, Germany.txt, etc."
        exit 1
    fi
    
    # Список файлов для обработки
    country_files=("$COUNTRIES_DIR"/*.txt)
    
    if [ ${#country_files[@]} -eq 0 ]; then
        echo "❌ Не найдено файлов стран в $COUNTRIES_DIR"
        exit 1
    fi
    
    echo "📁 Найдено файлов: ${#country_files[@]}"
    echo "⚡ В каждой подсети сканируется до $MAX_IPS_PER_SUBNET адресов"
    echo "📋 Белый список будет сохранен в: $WHITELIST_FILE"
    
    # Обрабатываем каждый файл
    for country_file in "${country_files[@]}"; do
        if [ -f "$country_file" ]; then
            # Полное сканирование (первые 200 IP каждой подсети)
            process_country_file "$country_file"
        fi
    done
    
    # Создаем финальный белый список
    create_final_whitelist
    
    # Финальный отчет
    echo ""
    echo "=========================================="
    echo "📈 ГЛОБАЛЬНЫЙ ОТЧЕТ"
    echo "=========================================="
    
    for summary_file in "$RESULTS_DIR"/*_summary.txt; do
        if [ -f "$summary_file" ]; then
            echo ""
            cat "$summary_file"
        fi
    done
    
    echo ""
    echo "🎯 Активные IP сохранены в: $RESULTS_DIR/"
    echo "📋 Белый список подсетей: ${RESULTS_DIR}/cidrwhitelist_final.txt"
    echo "💡 Для анализа используй:"
    echo "   cat $RESULTS_DIR/*_active.txt"
    echo "   cat ${RESULTS_DIR}/cidrwhitelist_final.txt"
    echo "⚡ Сканировано до $MAX_IPS_PER_SUBNET IP в каждой подсети"
    echo "🏢 Оператор: $OPERATOR"
}

# Запуск
main "$@"
