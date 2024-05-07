<?php declare(strict_types = 0);
/*
** Zabbix
** Copyright (C) 2001-2024 Zabbix SIA
**
** This program is free software; you can redistribute it and/or modify
** it under the terms of the GNU General Public License as published by
** the Free Software Foundation; either version 2 of the License, or
** (at your option) any later version.
**
** This program is distributed in the hope that it will be useful,
** but WITHOUT ANY WARRANTY; without even the implied warranty of
** MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the
** GNU General Public License for more details.
**
** You should have received a copy of the GNU General Public License
** along with this program; if not, write to the Free Software
** Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA  02110-1301, USA.
**/


namespace Widgets\PlainText\Actions;

use API,
	CControllerDashboardWidgetView,
	CControllerResponseData,
	CItemHelper,
	CSettingsHelper,
	Manager;

use	Widgets\PlainText\Includes\CWidgetFieldColumnsList;

class WidgetView extends CControllerDashboardWidgetView {

	protected function doAction(): void {
		$error = null;

		$name = $this->widget->getDefaultName();

		$data = [
			'name' => $this->getInput('name', $name),
			'layout' => $this->fields_values['layout'],
			'columns' => [],
			'items' => [],
			'sortorder' => $this->fields_values['sortorder'],
			'show_lines' => $this->fields_values['show_lines'],
			'show_timestamp' => $this->fields_values['show_timestamp'],
			'show_column_header' => $this->fields_values['show_column_header'],
			'error' => $error,
			'user' => [
				'debug_mode' => $this->getDebugMode()
			]
		];

		$db_items = [];

		$override_hostid = $this->fields_values['override_hostid'] ? $this->fields_values['override_hostid'][0] : '';

		if ($override_hostid !== '' && $this->isTemplateDashboard()) {
			$data['error'] = _('No data.');

			$this->setResponse(new CControllerResponseData($data));

			return;
		}

		if ($this->fields_values['columns']) {
			if ($override_hostid === '') {
				$db_items = API::Item()->get([
					'output' => ['itemid', 'value_type', 'units', 'valuemapid', 'history', 'trends'],
					'selectValueMap' => ['mappings'],
					'itemids' => array_column($this->fields_values['columns'], 'itemid'),
					'webitems' => true,
					'preservekeys' => true
				]);
			}
			else {
				$db_items = API::Item()->get([
					'output' => ['itemid', 'value_type', 'units', 'valuemapid', 'history', 'trends'],
					'selectValueMap' => ['mappings'],
					'itemids' => array_column($this->fields_values['columns'], 'itemid'),
					'hostids' => [$override_hostid],
					'webitems' => true,
					'preservekeys' => true
				]);
			}
		}

		if (!$db_items) {
			$data['error'] = _('No permissions to referred object or it does not exist!');

			$this->setResponse(new CControllerResponseData($data));

			return;
		}

		$columns_config = array_filter($this->fields_values['columns'], static function($column) use ($db_items) {
			return array_key_exists('itemid', $column) && array_key_exists($column['itemid'], $db_items);
		});

		$item_values_by_source = $this->getItemValuesByDataSource($db_items, $columns_config);

		if (!$item_values_by_source[CWidgetFieldColumnsList::HISTORY_DATA_HISTORY]
				&& !$item_values_by_source[CWidgetFieldColumnsList::HISTORY_DATA_TRENDS]) {
			$this->setResponse(new CControllerResponseData($data));

			return;
		}

		$columns_with_data = [];
		$items = [];

		foreach ($columns_config as $column) {
			if (array_key_exists($column['itemid'], $item_values_by_source[$column['history']])) {
				$column['item_values'] = [...$item_values_by_source[$column['history']][$column['itemid']]];

				if (in_array($column['item_value_type'], [ITEM_VALUE_TYPE_FLOAT, ITEM_VALUE_TYPE_UINT64])
						&& ($column['display'] == CWidgetFieldColumnsList::DISPLAY_BAR
							|| $column['display'] == CWidgetFieldColumnsList::DISPLAY_INDICATORS)) {

					if (!array_key_exists('min', $column) || $column['min'] === '') {
						$column['min'] = min(array_column($column['item_values'], 'value'));
					}

					if (!array_key_exists('max', $column) || $column['max'] === '') {
						$column['max'] = max(array_column($column['item_values'], 'value'));
					}
				}

				$items[$column['itemid']] = $db_items[$column['itemid']];
				$columns_with_data[] = $column;
			}
		}

		$this->setResponse(new CControllerResponseData([
			'name' => $this->getInput('name', $name),
			'columns' => $columns_with_data,
			'items' => $items,
			'layout' => $this->fields_values['layout'],
			'sortorder' => $this->fields_values['sortorder'],
			'show_timestamp' => (bool) $this->fields_values['show_timestamp'],
			'show_column_header' => $this->fields_values['show_column_header'],
			'show_lines' => $this->fields_values['show_lines'],
			'error' => $error,
			'user' => [
				'debug_mode' => $this->getDebugMode()
			]
		]));
	}

	private function getItemValuesByDataSource(array $items, array &$columns_config): array {
		$time_from = time() - timeUnitToSeconds(CSettingsHelper::get(CSettingsHelper::HISTORY_PERIOD));

		$items_by_source = $this->addDataSourceAndPrepareColumns($items, $columns_config, $time_from);

		$result = [
			CWidgetFieldColumnsList::HISTORY_DATA_HISTORY => [],
			CWidgetFieldColumnsList::HISTORY_DATA_TRENDS => []
		];

		if ($items_by_source[CWidgetFieldColumnsList::HISTORY_DATA_HISTORY]) {
			$result[CWidgetFieldColumnsList::HISTORY_DATA_HISTORY] = Manager::History()->getLastValues(
				$items_by_source[CWidgetFieldColumnsList::HISTORY_DATA_HISTORY], $this->fields_values['show_lines'],
				timeUnitToSeconds(CSettingsHelper::get(CSettingsHelper::HISTORY_PERIOD))
			);
		}

		if ($items_by_source[CWidgetFieldColumnsList::HISTORY_DATA_TRENDS]) {
			$result[CWidgetFieldColumnsList::HISTORY_DATA_TRENDS] = Manager::History()->getAggregatedValues(
				$items_by_source[CWidgetFieldColumnsList::HISTORY_DATA_TRENDS], AGGREGATE_LAST, $time_from
			);
		}

		return $result;
	}

	private function addDataSourceAndPrepareColumns(array $items, array &$columns_config, int $time): array {
		$items_with_source = [
			CWidgetFieldColumnsList::HISTORY_DATA_TRENDS => [],
			CWidgetFieldColumnsList::HISTORY_DATA_HISTORY => []
		];

		foreach ($columns_config as &$column) {
			$itemid = $column['itemid'];
			$item = $items[$itemid];
			$column['item_value_type'] = $item['value_type'];

			if (in_array($item['value_type'], [ITEM_VALUE_TYPE_FLOAT, ITEM_VALUE_TYPE_UINT64])) {
				if ($column['history'] == CWidgetFieldColumnsList::HISTORY_DATA_AUTO) {
					[$item] = CItemHelper::addDataSource([$item], $time);

					$column['history'] = $item['source'] === 'history'
						? CWidgetFieldColumnsList::HISTORY_DATA_HISTORY
						: CWidgetFieldColumnsList::HISTORY_DATA_TRENDS;
				}
				else {
					$item['source'] = $column['history'] == CWidgetFieldColumnsList::HISTORY_DATA_HISTORY
						? 'history'
						: 'trends';
				}

				$items_with_source[$column['history']][$itemid] = $item;
			}
			else {
				$column['history'] = CWidgetFieldColumnsList::HISTORY_DATA_HISTORY;
				$item['source'] = 'history';
				$items_with_source[CWidgetFieldColumnsList::HISTORY_DATA_HISTORY][$itemid] = $item;
			}
		}
		unset($column);

		return $items_with_source;
	}
}
