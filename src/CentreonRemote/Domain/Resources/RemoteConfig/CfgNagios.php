<?php

namespace CentreonRemote\Domain\Resources\RemoteConfig;

/**
 * Get broker configuration template
 */
class CfgNagios
{
    /**
     * Get template configuration
     * @todo move it as yml
     *
     * @param string $name the poller name
     * @param int $serverID the poller id
     * @return array the configuration template
     */
    public static function getConfiguration(string $name, int $serverID): array
    {
        return [
            'nagios_name'                                 => $name,
            'use_timezone'                                => null,
            'log_file'                                    => '/var/log/centreon-engine/centengine.log',
            'cfg_dir'                                     => '/etc/centreon-engine/',
            'temp_file'                                   => '/var/log/centreon-engine/centengine.tmp',
            'status_file'                                 => '/var/log/centreon-engine/status.dat',
            'status_update_interval'                      => '30',
            'nagios_user'                                 => 'centreon-engine',
            'nagios_group'                                => 'centreon-engine',
            'enable_notifications'                        => '1',
            'execute_service_checks'                      => '1',
            'accept_passive_service_checks'               => '1',
            'execute_host_checks'                         => '1',
            'accept_passive_host_checks'                  => '1',
            'enable_event_handlers'                       => '1',
            'log_rotation_method'                         => 'd',
            'log_archive_path'                            => '/var/log/centreon-engine/archives/',
            'check_external_commands'                     => '1',
            'external_command_buffer_slots'               => '4096',
            'command_check_interval'                      => '2s',
            'command_file'                                => '/var/lib/centreon-engine/rw/centengine.cmd',
            'downtime_file'                               => null,
            'comment_file'                                => null,
            'lock_file'                                   => '/var/lock/subsys/centengine.lock',
            'retain_state_information'                    => '1',
            'state_retention_file'                        => '/var/log/centreon-engine/retention.dat',
            'retention_update_interval'                   => '60',
            'use_retained_program_state'                  => '1',
            'use_retained_scheduling_info'                => '0',
            'retained_contact_host_attribute_mask'        => null,
            'retained_contact_service_attribute_mask'     => null,
            'retained_process_host_attribute_mask'        => null,
            'retained_process_service_attribute_mask'     => null,
            'retained_host_attribute_mask'                => null,
            'retained_service_attribute_mask'             => null,
            'use_syslog'                                  => '1',
            'log_notifications'                           => '1',
            'log_service_retries'                         => '0',
            'log_host_retries'                            => '0',
            'log_event_handlers'                          => '1',
            'log_initial_states'                          => '1',
            'log_external_commands'                       => '1',
            'log_passive_checks'                          => '1',
            'global_host_event_handler'                   => null,
            'global_service_event_handler'                => null,
            'sleep_time'                                  => '0.5',
            'service_inter_check_delay_method'            => 's',
            'Host_inter_check_delay_method'               => 's',
            'service_interleave_factor'                   => '2',
            'max_concurrent_checks'                       => '0',
            'max_service_check_spread'                    => '5',
            'max_host_check_spread'                       => '5',
            'check_result_reaper_frequency'               => '10',
            'max_check_result_reaper_time'                => '30',
            'interval_length'                             => '60',
            'auto_reschedule_checks'                      => '0',
            'auto_rescheduling_interval'                  => '30',
            'auto_rescheduling_window'                    => '180',
            'use_aggressive_host_checking'                => '0',
            'enable_flap_detection'                       => '0',
            'low_service_flap_threshold'                  => '20.0',
            'high_service_flap_threshold'                 => '30.0',
            'low_host_flap_threshold'                     => '20.0',
            'high_host_flap_threshold'                    => '30.0',
            'soft_state_dependencies'                     => '0',
            'service_check_timeout'                       => '60',
            'host_check_timeout'                          => '30',
            'event_handler_timeout'                       => '30',
            'notification_timeout'                        => '30',
            'ocsp_timeout'                                => '15',
            'ochp_timeout'                                => '15',
            'perfdata_timeout'                            => '5',
            'obsess_over_services'                        => '0',
            'ocsp_command'                                => null,
            'obsess_over_hosts'                           => '0',
            'ochp_command'                                => null,
            'process_performance_data'                    => '0',
            'host_perfdata_command'                       => null,
            'service_perfdata_command'                    => null,
            'host_perfdata_file'                          => null,
            'service_perfdata_file'                       => null,
            'host_perfdata_file_template'                 => null,
            'service_perfdata_file_template'              => null,
            'host_perfdata_file_mode'                     => '0',
            'service_perfdata_file_mode'                  => '0',
            'host_perfdata_file_processing_interval'      => '0',
            'service_perfdata_file_processing_interval'   => '0',
            'host_perfdata_file_processing_command'       => null,
            'service_perfdata_file_processing_command'    => null,
            'check_for_orphaned_services'                 => '1',
            'check_for_orphaned_hosts'                    => '1',
            'check_service_freshness'                     => '1',
            'service_freshness_check_interval'            => '60',
            'freshness_check_interval'                    => null,
            'check_host_freshness'                        => '0',
            'host_freshness_check_interval'               => '60',
            'date_format'                                 => 'us',
            'illegal_object_name_chars'                   => "~!$%^&*\"|'<>?,()=",
            'illegal_macro_output_chars'                  => "`~$^&\"|'<>",
            'use_regexp_matching'                         => '0',
            'use_true_regexp_matching'                    => '0',
            'admin_email'                                 => 'admin',
            'admin_pager'                                 => 'admin@localhost',
            'nagios_comment'                              => 'Centreon Engine configuration file',
            'nagios_activate'                             => '1',
            'event_broker_options'                        => '-1',
            'translate_passive_host_checks'               => '0',
            'nagios_server_id'                            => $serverID,
            'enable_predictive_host_dependency_checks'    => '1',
            'enable_predictive_service_dependency_checks' => '1',
            'cached_host_check_horizon'                   => '15',
            'cached_service_check_horizon'                => '15',
            'passive_host_checks_are_soft'                => '0',
            'use_large_installation_tweaks'               => '0',
            'enable_environment_macros'                   => '0',
            'use_setpgid'                                 => '1',
            'additional_freshness_latency'                => '15',
            'debug_file'                                  => '/var/log/centreon-engine/centengine.debug',
            'debug_level'                                 => '0',
            'debug_level_opt'                             => '0',
            'debug_verbosity'                             => '1',
            'max_debug_file_size'                         => '1000000000',
            'daemon_dumps_core'                           => '0',
            'cfg_file'                                    => 'centengine.cfg',
            'log_pid'                                     => '1',
        ];
    }
}