<?php
/*
** ZABBIX
** Copyright (C) 2000-2009 SIA Zabbix
**
** This program is free software; you can redistribute it and/or modify
** it under the terms of the GNU General Public License as published by
** the Free Software Foundation; either version 2 of the License, or
** (at your option) any later version.
**
** This program is distributed in the hope that it will be useful,
** but WITHOUT ANY WARRANTY; without even the implied warranty of
** MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
** GNU General Public License for more details.
**
** You should have received a copy of the GNU General Public License
** along with this program; if not, write to the Free Software
** Foundation, Inc., 675 Mass Ave, Cambridge, MA 02139, USA.
**/
?>
<?php
/**
 * File containing CAlert class for API.
 * @package API
 */
/**
 * Class containing methods for operations with Alerts
 *
 */
class CAlert {

	public static $error = array();

	/**
	 * Get Alerts data
	 *
	 * {@source}
	 * @access public
	 * @static
	 * @since 1.8
	 * @version 1
	 *
	 * @param _array $options
	 * @param array $options['itemids']
	 * @param array $options['hostids']
	 * @param array $options['groupids']
	 * @param array $options['alertids']
	 * @param array $options['applicationids']
	 * @param array $options['status']
	 * @param array $options['templated_items']
	 * @param array $options['editable']
	 * @param array $options['extendoutput']
	 * @param array $options['count']
	 * @param array $options['pattern']
	 * @param array $options['limit']
	 * @param array $options['order']
	 * @return array|int item data as array or false if error
	 */
	public static function get($options=array()){
		global $USER_DETAILS;

		$result = array();
		$user_type = $USER_DETAILS['type'];
		$userid = $USER_DETAILS['userid'];

		$sort_columns = array('alertid','clock','eventid','status'); // allowed columns for sorting


		$sql_parts = array(
			'select' => array('alerts' => 'a.alertid'),
			'from' => array('a' => 'alerts a'),
			'where' => array(),
			'order' => array(),
			'limit' => null,
			);

		$def_options = array(
			'nodeids'				=> null,
			'groupids'				=> null,
			'hostids'				=> null,
			'alertids'				=> null,
			'triggerids'			=> null,
			'eventids'				=> null,
			'actionids'				=> null,
			'mediatypeids'			=> null,
			'userids'				=> null,
			'nopermissions'			=> null,

// filter
			'status'				=> null,
			'retries'				=> null,
			'sendto'				=> null,
			'alerttype'				=> null,
			'time_from'				=> null,
			'time_till'				=> null,

// OutPut
			'extendoutput'			=> null,
			'select_mediatypes'		=> null,
			'select_users'			=> null,
			'count'					=> null,

			'sortfield'				=> '',
			'sortorder'				=> '',
			'limit'					=> null
		);

		$options = array_merge($def_options, $options);


// editable + PERMISSION CHECK
		if(defined('ZBX_API_REQUEST')){
			$options['nopermissions'] = false;
		}

		if((USER_TYPE_SUPER_ADMIN == $user_type) || $options['nopermissions']){
		}
		else{
			$permission = $options['editable']?PERM_READ_WRITE:PERM_READ_ONLY;

			$sql_parts['from']['e'] = 'events e';
			$sql_parts['from']['i'] = 'items i';
			$sql_parts['from']['hg'] = 'hosts_groups hg';
			$sql_parts['from']['r'] = 'rights r';
			$sql_parts['from']['ug'] = 'users_groups ug';

			$sql_parts['where']['ae'] = 'a.eventid=e.eventid';
			$sql_parts['where']['e'] = 'e.object='.EVENT_OBJECT_TRIGGER;
			$sql_parts['where']['ef'] = 'e.objectid=f.triggerid';
			$sql_parts['where']['fi'] = 'f.itemid=i.itemid';
			$sql_parts['where']['hgi'] = 'hg.hostid=i.hostid';
			$sql_parts['where'][] = 'r.id=hg.groupid ';
			$sql_parts['where'][] = 'r.groupid=ug.usrgrpid';
			$sql_parts['where'][] = 'ug.userid='.$userid;
			$sql_parts['where'][] = 'r.permission>='.$permission;
			$sql_parts['where'][] = 'NOT EXISTS( '.
											' SELECT ff.triggerid '.
											' FROM functions ff, items ii '.
											' WHERE ff.triggerid=e.objectid '.
												' AND ff.itemid=ii.itemid '.
												' AND EXISTS( '.
													' SELECT hgg.groupid '.
													' FROM hosts_groups hgg, rights rr, users_groups gg '.
													' WHERE hgg.hostid=ii.hostid '.
														' AND rr.id=hgg.groupid '.
														' AND rr.groupid=gg.usrgrpid '.
														' AND gg.userid='.$userid.
														' AND rr.permission<'.$permission.'))';
		}

// nodeids
		$nodeids = $options['nodeids'] ? $options['nodeids'] : get_current_nodeid(false);

// groupids
		if(!is_null($options['groupids'])){
			zbx_value2array($options['groupids']);

			if(!is_null($options['extendoutput'])){
				$sql_parts['select']['groupid'] = 'hg.groupid';
			}

			$sql_parts['from']['f'] = 'functions f';
			$sql_parts['from']['i'] = 'items i';
			$sql_parts['from']['hg'] = 'hosts_groups hg';

			$sql_parts['where']['hgi'] = 'hg.hostid=i.hostid';
			$sql_parts['where']['e'] = 'e.object='.EVENT_OBJECT_TRIGGER;
			$sql_parts['where']['ef'] = 'e.objectid=f.triggerid';
			$sql_parts['where']['fi'] = 'f.itemid=i.itemid';
			$sql_parts['where']['hg'] = DBcondition('hg.groupid', $options['groupids']);
		}

// hostids
		if(!is_null($options['hostids'])){
			zbx_value2array($options['hostids']);

			if(!is_null($options['extendoutput'])){
				$sql_parts['select']['hostid'] = 'i.hostid';
			}

			$sql_parts['from']['f'] = 'functions f';
			$sql_parts['from']['i'] = 'items i';

			$sql_parts['where']['i'] = DBcondition('i.hostid', $options['hostids']);
			$sql_parts['where']['e'] = 'e.object='.EVENT_OBJECT_TRIGGER;
			$sql_parts['where']['ef'] = 'e.objectid=f.triggerid';
			$sql_parts['where']['fi'] = 'f.itemid=i.itemid';
		}

// alertids
		if(!is_null($options['alertids'])){
			zbx_value2array($options['alertids']);

			$sql_parts['where'][] = DBcondition('a.alertid', $options['alertids']);
		}

// triggerids
		if(!is_null($options['triggerids'])){
			zbx_value2array($options['triggerids']);

			if(!is_null($options['extendoutput'])){
				$sql_parts['select']['actionid'] = 'a.actionid';
			}
			
			$sql_parts['where']['ae'] = 'a.eventid=e.eventid';
			$sql_parts['where']['e'] = 'e.object='.EVENT_OBJECT_TRIGGER;
			$sql_parts['where'][] = DBcondition('e.objectid', $options['triggerids']);
		}

// actionids
		if(!is_null($options['actionids'])){
			zbx_value2array($options['actionids']);

			if(!is_null($options['extendoutput'])){
				$sql_parts['select']['actionid'] = 'a.actionid';
			}
			
			$sql_parts['where'][] = DBcondition('a.actionid', $options['actionids']);
		}
		
// userids
		if(!is_null($options['userids'])){
			zbx_value2array($options['userids']);

			if(!is_null($options['extendoutput'])){
				$sql_parts['select']['userid'] = 'a.userid';
			}
			
			$sql_parts['where'][] = DBcondition('a.userid', $options['userids']);
		}
		
// mediatypeids
		if(!is_null($options['mediatypeids'])){
			zbx_value2array($options['mediatypeids']);

			if(!is_null($options['extendoutput'])){
				$sql_parts['select']['mediatypeid'] = 'a.mediatypeid';
			}
			
			$sql_parts['where'][] = DBcondition('a.mediatypeid', $options['mediatypeids']);
		}

// status
		if(!is_null($options['status'])){
			$sql_parts['where'][] = 'a.status='.$options['status'];
		}

// sendto
		if(!is_null($options['sendto'])){
			$sql_parts['where'][] = 'a.sendto='.$options['sendto'];
		}
		
// alerttype
		if(!is_null($options['alerttype'])){
			$sql_parts['where'][] = 'a.alerttype='.$options['alerttype'];
		}

// time_from
		if(!is_null($options['time_from'])){
			$sql_parts['where'][] = 'a.clock>'.$options['time_from'];
		}

// time_till
		if(!is_null($options['time_till'])){
			$sql_parts['where'][] = 'a.clock<'.$options['time_till'];
		}

// extendoutput
		if(!is_null($options['extendoutput'])){
			$sql_parts['select']['alerts'] = 'a.*';
		}

// count
		if(!is_null($options['count'])){
			$options['sortfield'] = '';

			$sql_parts['select'] = array('COUNT(DISTINCT a.alertid) as rowscount');
		}
		
// order
// restrict not allowed columns for sorting
		$options['sortfield'] = str_in_array($options['sortfield'], $sort_columns) ? $options['sortfield'] : '';
		if(!zbx_empty($options['sortfield'])){
			$sortorder = ($options['sortorder'] == ZBX_SORT_DOWN)?ZBX_SORT_DOWN:ZBX_SORT_UP;

			$sql_parts['order'][] = 'a.'.$options['sortfield'].' '.$sortorder;

			if(!str_in_array('a.'.$options['sortfield'], $sql_parts['select']) && !str_in_array('a.*', $sql_parts['select'])){
				$sql_parts['select'][] = 'a.'.$options['sortfield'];
			}
		}

// limit
		if(zbx_ctype_digit($options['limit']) && $options['limit']){
			$sql_parts['limit'] = $options['limit'];
		}
//---------------

		$alertids = array();
		$userids = array();
		$mediatypeids = array();

		$sql_parts['select'] = array_unique($sql_parts['select']);
		$sql_parts['from'] = array_unique($sql_parts['from']);
		$sql_parts['where'] = array_unique($sql_parts['where']);
		$sql_parts['order'] = array_unique($sql_parts['order']);

		$sql_select = '';
		$sql_from = '';
		$sql_where = '';
		$sql_order = '';
		if(!empty($sql_parts['select']))	$sql_select.= implode(',',$sql_parts['select']);
		if(!empty($sql_parts['from']))		$sql_from.= implode(',',$sql_parts['from']);
		if(!empty($sql_parts['where']))		$sql_where.= ' AND '.implode(' AND ',$sql_parts['where']);
		if(!empty($sql_parts['order']))		$sql_order.= ' ORDER BY '.implode(',',$sql_parts['order']);
		$sql_limit = $sql_parts['limit'];

		$sql = 'SELECT '.$sql_select.
				' FROM '.$sql_from.
				' WHERE '.DBin_node('a.alertid', $nodeids).
					$sql_where.
				$sql_order;
		$db_res = DBselect($sql, $sql_limit);
		while($alert = DBfetch($db_res)){
			if($options['count'])
				$result = $alert;
			else{
				$alertids[$alert['alertid']] = $alert['alertid'];
				$userids[$alert['userid']] = $alert['userid'];
				$mediatypeids[$alert['mediatypeid']] = $alert['mediatypeid'];

				if(is_null($options['extendoutput'])){
					$result[$alert['alertid']] = $alert['alertid'];
				}
				else{
					if(!isset($result[$alert['alertid']])) $result[$alert['alertid']]= array();

					if(!is_null($options['select_mediatypes']) && !isset($result[$alert['alertid']]['mediatypeids'])){
						$result[$alert['alertid']]['mediatypeids'] = array();
						$result[$alert['alertid']]['mediatypes'] = array();
					}
					if(!is_null($options['select_users']) && !isset($result[$alert['alertid']]['userids'])){
						$result[$alert['alertid']]['userids'] = array();
						$result[$alert['alertid']]['users'] = array();
					}

// hostids
					if(isset($alert['hostid'])){
						if(!isset($result[$alert['alertid']]['hostids'])) $result[$alert['alertid']]['hostids'] = array();

						$result[$alert['alertid']]['hostids'][$alert['hostid']] = $alert['hostid'];
						unset($alert['hostid']);
					}
// userids
					if(isset($alert['userid'])){
						if(!isset($result[$alert['alertid']]['userids'])) $result[$alert['alertid']]['userids'] = array();

						$result[$alert['alertid']]['userids'][$alert['userid']] = $alert['userid'];
					}
// mediatypeids
					if(isset($alert['mediatypeid'])){
						if(!isset($result[$alert['alertid']]['mediatypeids'])) $result[$alert['alertid']]['mediatypeids'] = array();

						$result[$alert['alertid']]['mediatypeids'][$alert['mediatypeid']] = $alert['mediatypeid'];
					}
					
					$result[$alert['alertid']] += $alert;
				}
			}
		}

		if(is_null($options['extendoutput']) || !is_null($options['count'])) return $result;

// Adding Objects
		$users = array();
		$mediatypes = array();

// Adding Users
		if($options['select_users']){
			$obj_params = array('extendoutput' => 1, 'userids' => $userids);
			$users = CUser::get($obj_params);
		}
		
// Adding MediaTypes
		if($options['select_mediatypes']){
			$sql = 'SELECT mt.* FROM media_type mt WHERE '.DBcondition('mt.mediatypeid', $mediatypeids);
			$res = DBselect($sql);
			while($media = DBfetch($res)){
				$mediatypes[$media['mediatypeid']] = $media;
			}
		}
		
		foreach($result as $alertid => $alert){
			if(isset($mediatypes[$alert['mediatypeid']])){
				$result[$alertid]['mediatypeids'][$alert['mediatypeid']] = $alert['mediatypeid'];
				$result[$alertid]['mediatypes'][$alert['mediatypeid']] = $mediatypes[$alert['mediatypeid']];
			}
			
			if(isset($users[$alert['userid']])){
				$result[$alertid]['userids'][$alert['userid']] = $alert['userid'];
				$result[$alertid]['users'][$alert['userid']] = $users[$alert['userid']];
			}
		}

	return $result;
	}

/**
 * Add alerts
 *
 * {@source}
 * @access public
 * @static
 * @since 1.8
 * @version 1
 *
 * @param _array $alerts multidimensional array with alerts data
 * @param array $alerts[0,...]['expression']
 * @param array $alerts[0,...]['description']
 * @param array $alerts[0,...]['type'] OPTIONAL
 * @param array $alerts[0,...]['priority'] OPTIONAL
 * @param array $alerts[0,...]['status'] OPTIONAL
 * @param array $alerts[0,...]['comments'] OPTIONAL
 * @param array $alerts[0,...]['url'] OPTIONAL
 * @return boolean
 */
	public static function add($alerts){

		$alertids = array();
		DBstart(false);

		$result = false;
		foreach($alerts as $num => $alert){
			$alert_db_fields = array(
				'actionid'		=> null,
				'eventid'		=> null,
				'userid'		=> null,
				'clock'			=> time(),
				'mediatypeid'	=> 0,
				'sendto'		=> null,
				'subject'		=> '',
				'message'		=> '',
				'status'		=> ALERT_STATUS_NOT_SENT,
				'retries'		=> 0,
				'error'			=> '',
				'nextcheck'		=> null,
				'esc_step'		=> 0,
				'alerttype'		=> ALERT_TYPE_MESSAGE
			);

			if(!check_db_fields($alert_db_fields, $alert)){
				$result = false;
				break;
			}

			$alertid = get_dbid('alerts', 'alertid');
			$sql = 'INSERT INTO alerts '.
					'(alertid, actionid, eventid, userid, mediatypeid, clock, sendto, subject, message, status, retries, error, nextcheck, esc_step, alerttype) '.
					' VALUES ('.$alertid.','.$alert['actionid'].','.$alert['eventid'].','.$alert['userid'].','.$alert['mediatypeid'].','.
								$alert['clock'].','.zbx_dbstr($alert['sentto']).','.zbx_dbstr($alert['subject']).','.zbx_dbstr($alert['message']).','.
								$alert['status'].','.$alert['retries'].','.zbx_dbstr($alert['error']).','.$alert['nextcheck'].','.
								$alert['esc_step'].','.$alert['alerttype'].' )';
			$result = DBexecute($sql);
			if(!$result) break;
			$alertids[$alertid] = $alertid;
		}

		$result = DBend($result);
		if($result)
			return $alertids;
		else{
			self::$error[] = array('error' => ZBX_API_ERROR_INTERNAL, 'data' => 'Internal zabbix error');
			return false;
		}
	}

/**
 * Delete alerts
 *
 * {@source}
 * @access public
 * @static
 * @since 1.8
 * @version 1
 *
 * @param _array $alertids
 * @return boolean
 */
	public static function delete($alertids){
		zbx_value2array($alertids);
		
		$sql = 'DELETE FROM alerts WHERE '.DBcondition('alertid', $alertids);
		$result = DBexecute($sql);
		if($result)
			return $result;
		else{
			self::$error[] = array('error' => ZBX_API_ERROR_INTERNAL, 'data' => 'Internal zabbix error');
			return false;
		}
	}
}
?>
