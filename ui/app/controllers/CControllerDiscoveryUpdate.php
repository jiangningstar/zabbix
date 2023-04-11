<?php declare(strict_types = 0);
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


class CControllerDiscoveryUpdate extends CController {

	protected function init(): void {
		$this->setPostContentType(self::POST_CONTENT_TYPE_JSON);
	}

	protected function checkInput() {
		$fields = [
			'druleid' =>				'required|db drules.druleid',
			'name' =>					'required|db drules.name|not_empty',
			'proxy_hostid' =>			'db drules.proxy_hostid',
			'iprange' =>				'required|db drules.iprange|not_empty|flags '.P_CRLF,
			'delay' =>					'required|db drules.delay|not_empty',
			'status' =>					'db drules.status|in '.implode(',', [DRULE_STATUS_ACTIVE, DRULE_STATUS_DISABLED]),
			'uniqueness_criteria' =>	'string',
			'host_source' =>			'string',
			'name_source' =>			'string',
			'dchecks' =>				'required|array'
		];

		$ret = $this->validateInput($fields);

		if (!$ret) {
			$this->setResponse(
				new CControllerResponseData(['main_block' => json_encode([
					'error' => [
						'title' => _('Cannot create discovery rule'),
						'messages' => array_column(get_and_clear_messages(), 'message')
					]
				])])
			);
		}

		return $ret;
	}

	protected function checkPermissions() {
		if (!$this->checkAccess(CRoleHelper::UI_CONFIGURATION_DISCOVERY)) {
			return false;
		}

		return (bool) API::DRule()->get([
			'output' => [],
			'druleids' => $this->getInput('druleid'),
			'countOutput' => true,
			'editable' => true
		]);
	}

	protected function doAction() {
		$drule = [];
		$this->getInputs($drule, ['druleid', 'name', 'proxy_hostid', 'iprange', 'delay', 'status', 'dchecks']);
		$uniq = $this->getInput('uniqueness_criteria', 0);

		foreach ($drule['dchecks'] as $dcnum => $check) {
			if (substr($check['dcheckid'], 0, 3) === 'new') {
				unset($drule['dchecks'][$dcnum]['dcheckid']);
			}

			$drule['dchecks'][$dcnum]['uniq'] = ($uniq == $dcnum) ? 1 : 0;
		}

		$result = API::DRule()->update($drule);

		$output = [];

		if ($result) {
			$output['success']['title'] = _('Discovery rule updated');

			if ($messages = get_and_clear_messages()) {
				$output['success']['messages'] = array_column($messages, 'message');
			}
		}
		else {
			$output['error'] = [
				'title' => _('Cannot update discovery rule'),
				'messages' => array_column(get_and_clear_messages(), 'message')
			];
		}

		$this->setResponse(new CControllerResponseData(['main_block' => json_encode($output)]));
	}
}
