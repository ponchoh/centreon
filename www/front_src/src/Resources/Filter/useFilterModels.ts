import { useTranslation } from 'react-i18next';
import { isNil } from 'ramda';

import {
  labelAcknowledged,
  labelInDowntime,
  labelUnhandled,
  labelHost,
  labelService,
  labelOk,
  labelUp,
  labelWarning,
  labelDown,
  labelCritical,
  labelUnreachable,
  labelUnknown,
  labelPending,
  labelAll,
  labelNewFilter,
  labelUnhandledProblems,
  labelResourceProblems,
} from '../translatedLabels';

import { Filter, CriteriaValue } from './models';

interface FilterModelsContext {
  allFilter: Filter;
  criteriaValueNameById: { [id: string]: string };
  isCustom: (filter: Filter) => boolean;
  newFilter: Filter;
  resourceProblemsFilter: Filter;
  resourceTypes: Array<CriteriaValue>;
  standardFilterById: { [id: string]: Filter };
  states: Array<CriteriaValue>;
  statuses: Array<CriteriaValue>;
  unhandledProblemsFilter: Filter;
}

const useFilterModels = (): FilterModelsContext => {
  const { t } = useTranslation();

  const criteriaValueNameById = {
    CRITICAL: t(labelCritical),
    DOWN: t(labelDown),
    OK: t(labelOk),
    PENDING: t(labelPending),
    UNKNOWN: t(labelUnknown),
    UNREACHABLE: t(labelUnreachable),
    UP: t(labelUp),
    WARNING: t(labelWarning),
    acknowledged: t(labelAcknowledged),
    host: t(labelHost),
    in_downtime: t(labelInDowntime),
    service: t(labelService),
    unhandled_problems: t(labelUnhandled),
  };

  const unhandledStateId = 'unhandled_problems';
  const unhandledState = {
    id: unhandledStateId,
    name: criteriaValueNameById[unhandledStateId],
  };

  const acknowledgedStateId = 'acknowledged';
  const acknowledgedState = {
    id: 'acknowledged',
    name: criteriaValueNameById[acknowledgedStateId],
  };

  const inDowntimeStateId = 'in_downtime';
  const inDowntimeState = {
    id: inDowntimeStateId,
    name: criteriaValueNameById[inDowntimeStateId],
  };

  const states = [unhandledState, acknowledgedState, inDowntimeState];

  const hostResourceTypeId = 'host';
  const hostResourceType = {
    id: hostResourceTypeId,
    name: criteriaValueNameById[hostResourceTypeId],
  };

  const serviceResourceTypeId = 'service';
  const serviceResourceType = {
    id: serviceResourceTypeId,
    name: criteriaValueNameById[serviceResourceTypeId],
  };

  const resourceTypes = [hostResourceType, serviceResourceType];

  const okStatusId = 'OK';
  const okStatus = { id: okStatusId, name: criteriaValueNameById[okStatusId] };

  const upStatusId = 'UP';
  const upStatus = { id: upStatusId, name: criteriaValueNameById[upStatusId] };

  const warningStatusId = 'WARNING';
  const warningStatus = {
    id: warningStatusId,
    name: criteriaValueNameById[warningStatusId],
  };

  const downStatusId = 'DOWN';
  const downStatus = {
    id: downStatusId,
    name: criteriaValueNameById[downStatusId],
  };

  const criticalStatusId = 'CRITICAL';
  const criticalStatus = {
    id: criticalStatusId,
    name: criteriaValueNameById[criticalStatusId],
  };

  const unreachableStatusId = 'UNREACHABLE';
  const unreachableStatus = {
    id: unreachableStatusId,
    name: criteriaValueNameById[unreachableStatusId],
  };

  const unknownStatusId = 'UNKNOWN';
  const unknownStatus = {
    id: unknownStatusId,
    name: criteriaValueNameById[unknownStatusId],
  };

  const pendingStatusId = 'PENDING';
  const pendingStatus = {
    id: pendingStatusId,
    name: criteriaValueNameById[pendingStatusId],
  };

  const statuses = [
    okStatus,
    upStatus,
    warningStatus,
    downStatus,
    criticalStatus,
    unreachableStatus,
    unknownStatus,
    pendingStatus,
  ];

  const allFilter = {
    criterias: {
      hostGroups: [],
      resourceTypes: [],
      search: undefined,
      serviceGroups: [],
      states: [],
      statuses: [],
    },
    id: 'all',
    name: t(labelAll),
  };

  const newFilter = {
    id: '',
    name: t(labelNewFilter),
  } as Filter;

  const unhandledProblemsFilter: Filter = {
    criterias: {
      hostGroups: [],
      resourceTypes: [],
      search: undefined,
      serviceGroups: [],
      states: [unhandledState],
      statuses: [warningStatus, downStatus, criticalStatus, unknownStatus],
    },
    id: 'unhandled_problems',
    name: t(labelUnhandledProblems),
  };

  const resourceProblemsFilter: Filter = {
    criterias: {
      hostGroups: [],
      resourceTypes: [],
      search: undefined,
      serviceGroups: [],
      states: [],
      statuses: [warningStatus, downStatus, criticalStatus, unknownStatus],
    },
    id: 'resource_problems',
    name: t(labelResourceProblems),
  };

  const standardFilterById = {
    all: allFilter,
    resource_problems: resourceProblemsFilter,
    unhandled_problems: unhandledProblemsFilter,
  };

  const isCustom = ({ id }: Filter): boolean => {
    return isNil(standardFilterById[id]);
  };

  return {
    allFilter,
    criteriaValueNameById,
    isCustom,
    newFilter,
    resourceProblemsFilter,
    resourceTypes,
    standardFilterById,
    states,
    statuses,
    unhandledProblemsFilter,
  };
};

export default useFilterModels;