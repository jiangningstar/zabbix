<?php
/*
** Zabbix
** Copyright (C) 2001-2023 Zabbix SIA
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


/**
 * This controller is used by gtlc.js to update time selector date and time interval in user's profile.
 */
class CControllerTimeSelectorUpdate extends CController {

	public static $profiles = ['web.dashboard.filter', 'web.charts.filter', 'web.httpdetails.filter',
		'web.problem.filter', 'web.auditlog.filter', 'web.actionlog.filter', 'web.item.graph.filter',
		'web.toptriggers.filter', 'web.avail_report.filter', CControllerHost::FILTER_IDX, CControllerProblem::FILTER_IDX
	];

	public function init() {
		$this->disableCsrfValidation();
	}

	protected function checkInput(): bool {
		$fields = [
			'method' =>			'required|in increment,decrement,zoomout,rangechange,rangeoffset',
			'idx' =>			'required|in '.implode(',', static::$profiles),
			'idx2' =>			'required|id',
			'from' =>			'required|string',
			'to' =>				'required|string',
			'from_offset' =>	'int32|ge 0',
			'to_offset' =>		'int32|ge 0'
		];

		$ret = $this->validateInput($fields);

		if ($ret && $this->getInput('method') === 'rangeoffset') {
			$validator = new CNewValidator($this->getInputAll(), [
				'from_offset' => 'required',
				'to_offset' => 'required'
			]);

			foreach ($validator->getAllErrors() as $error) {
				info($error);
			}

			if ($validator->isErrorFatal() || $validator->isError()) {
				$ret = false;
			}
		}

		if (!$ret) {
			$this->setResponse(
				new CControllerResponseData(['main_block' => json_encode([
					'error' => [
						'messages' => array_column(get_and_clear_messages(), 'message')
					]
				])])
			);
		}

		return $ret;
	}

	protected function checkPermissions(): bool {
		return $this->getUserType() >= USER_TYPE_ZABBIX_USER;
	}

	protected function doAction() {
		$time_period_service = new CTimePeriodService($this->getInput('from'), $this->getInput('to'));

		$fields_errors = $time_period_service->getErrors();

		if (!$fields_errors) {
			switch ($this->getInput('method')) {
				case 'increment':
					$time_period_service->increment();
					break;

				case 'decrement':
					$time_period_service->decrement();
					break;

				case 'zoomout':
					$time_period_service->zoomOut();
					break;

				case 'rangechange':
					$time_period_service->rangeChange();
					break;

				case 'rangeoffset':
					$time_period_service->rangeOffset($this->getInput('from_offset'), $this->getInput('to_offset'));
					break;
			}

			$fields_errors = $time_period_service->getErrors();
		}

		if ($fields_errors) {
			$output = ['fields_errors' => $fields_errors];
		}
		else {
			$data = $time_period_service->getData();

			updateTimeSelectorPeriod([
				'profileIdx' => $this->getInput('idx'),
				'profileIdx2' => $this->getInput('idx2'),
				'from' => $data['from'],
				'to' => $data['to']
			]);

			$output = [
				'label' => relativeDateToText($data['from'], $data['to']),
				'from' => $data['from'],
				'from_ts' => $data['from_ts'],
				'from_date' => date(ZBX_FULL_DATE_TIME, $data['from_ts']),
				'to' => $data['to'],
				'to_ts' => $data['to_ts'],
				'to_date' => date(ZBX_FULL_DATE_TIME, $data['to_ts']),
			] + getTimeselectorActions($data['from'], $data['to']);
		}

		$this->setResponse(new CControllerResponseData(['main_block' => json_encode($output)]));
	}
}
