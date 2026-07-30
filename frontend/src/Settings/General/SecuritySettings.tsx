import React, { FocusEvent, useCallback, useState } from 'react';
import CommandNames from 'Commands/CommandNames';
import { useExecuteCommand } from 'Commands/useCommands';
import FieldSet from 'Components/FieldSet';
import FormGroup from 'Components/Form/FormGroup';
import FormInputButton from 'Components/Form/FormInputButton';
import FormInputGroup from 'Components/Form/FormInputGroup';
import FormLabel from 'Components/Form/FormLabel';
import { EnhancedSelectInputValue } from 'Components/Form/Select/EnhancedSelectInput';
import Icon from 'Components/Icon';
import ClipboardButton from 'Components/Link/ClipboardButton';
import ConfirmModal from 'Components/Modal/ConfirmModal';
import { icons, inputTypes, kinds } from 'Helpers/Props';
import { useShowAdvancedSettings } from 'Settings/advancedSettingsStore';
import { InputChanged } from 'typings/inputs';
import { PendingSection } from 'typings/pending';
import translate from 'Utilities/String/translate';
import { GeneralSettingsModel } from './useGeneralSettings';

export const authenticationMethodOptions: EnhancedSelectInputValue<string>[] = [
  {
    key: 'none',
    get value() {
      return translate('None');
    },
    isDisabled: true,
  },
  {
    key: 'external',
    get value() {
      return translate('External');
    },
    isHidden: true,
  },
  {
    key: 'basic',
    get value() {
      return translate('AuthBasic');
    },
    isDisabled: true,
    isHidden: true,
  },
  {
    key: 'forms',
    get value() {
      return translate('AuthForm');
    },
  },
];

export const authenticationRequiredOptions: EnhancedSelectInputValue<string>[] =
  [
    {
      key: 'enabled',
      get value() {
        return translate('Enabled');
      },
    },
    {
      key: 'disabledForLocalHost',
      get value() {
        return translate('DisabledForLocalhost');
      },
    },
    {
      key: 'disabledForLocalAddresses',
      get value() {
        return translate('DisabledForLocalAddresses');
      },
    },
    {
      key: 'disabledForCustomAddresses',
      get value() {
        return translate('DisabledForCustomAddresses');
      },
    },
    {
      key: 'disabled',
      get value() {
        return translate('Disabled');
      },
    },
  ];

// Selecting one of these values weakens authentication protection and
// requires the user to confirm they understand the risk before it takes
// effect. disabledForLocalHost is excluded since it only ever bypasses
// authentication for requests originating from the machine itself.
const riskyAuthenticationRequiredValues = [
  'disabled',
  'disabledForLocalAddresses',
  'disabledForCustomAddresses',
];

const certificateValidationOptions: EnhancedSelectInputValue<string>[] = [
  {
    key: 'enabled',
    get value() {
      return translate('Enabled');
    },
  },
  {
    key: 'disabledForLocalAddresses',
    get value() {
      return translate('DisabledForLocalAddresses');
    },
  },
  {
    key: 'disabled',
    get value() {
      return translate('Disabled');
    },
  },
];

export const xForwardedForTrustLevelOptions: EnhancedSelectInputValue<string>[] =
  [
    {
      key: 'rfc1918',
      get value() {
        return translate('XForwardedForTrustRfc1918');
      },
    },
    {
      key: 'custom',
      get value() {
        return translate('XForwardedForTrustCustom');
      },
    },
    {
      key: 'disabled',
      get value() {
        return translate('Disabled');
      },
    },
  ];

interface SecuritySettingsProps {
  authenticationMethod: PendingSection<GeneralSettingsModel>['authenticationMethod'];
  authenticationRequired: PendingSection<GeneralSettingsModel>['authenticationRequired'];
  username: PendingSection<GeneralSettingsModel>['username'];
  password: PendingSection<GeneralSettingsModel>['password'];
  passwordConfirmation: PendingSection<GeneralSettingsModel>['passwordConfirmation'];
  apiKey: PendingSection<GeneralSettingsModel>['apiKey'];
  certificateValidation: PendingSection<GeneralSettingsModel>['certificateValidation'];
  xForwardedForTrustLevel: PendingSection<GeneralSettingsModel>['xForwardedForTrustLevel'];
  trustedProxyCidrs: PendingSection<GeneralSettingsModel>['trustedProxyCidrs'];
  authenticationRequiredCidrs: PendingSection<GeneralSettingsModel>['authenticationRequiredCidrs'];
  allowRfc1918UrlsFromExternalSources: PendingSection<GeneralSettingsModel>['allowRfc1918UrlsFromExternalSources'];
  isResettingApiKey: boolean;
  onInputChange: (change: InputChanged) => void;
}

function SecuritySettings({
  authenticationMethod,
  authenticationRequired,
  username,
  password,
  passwordConfirmation,
  apiKey,
  certificateValidation,
  xForwardedForTrustLevel,
  trustedProxyCidrs,
  authenticationRequiredCidrs,
  allowRfc1918UrlsFromExternalSources,
  isResettingApiKey,
  onInputChange,
}: SecuritySettingsProps) {
  const executeCommand = useExecuteCommand();
  const showAdvancedSettings = useShowAdvancedSettings();

  const [isConfirmApiKeyResetModalOpen, setIsConfirmApiKeyResetModalOpen] =
    useState(false);
  const [isConfirmAllowRfc1918ModalOpen, setIsConfirmAllowRfc1918ModalOpen] =
    useState(false);
  const [
    isConfirmAuthenticationRequiredModalOpen,
    setIsConfirmAuthenticationRequiredModalOpen,
  ] = useState(false);
  const [
    pendingAuthenticationRequiredValue,
    setPendingAuthenticationRequiredValue,
  ] = useState<string | null>(null);

  const handleApikeyFocus = useCallback(
    (event: FocusEvent<HTMLInputElement, Element>) => {
      event.target.select();
    },
    []
  );

  const handleResetApiKeyPress = useCallback(() => {
    setIsConfirmApiKeyResetModalOpen(true);
  }, []);

  const handleConfirmResetApiKey = useCallback(() => {
    setIsConfirmApiKeyResetModalOpen(false);

    executeCommand({ name: CommandNames.ResetApiKey });
  }, [executeCommand]);

  const handleCloseResetApiKeyModal = useCallback(() => {
    setIsConfirmApiKeyResetModalOpen(false);
  }, []);

  const handleAllowRfc1918Change = useCallback(
    ({ name, value }: InputChanged<boolean>) => {
      // Only interrupt with a warning when moving TO the less-secure
      // (enabled) state; re-disabling it is always safe and needs no
      // confirmation.
      if (value) {
        setIsConfirmAllowRfc1918ModalOpen(true);
      } else {
        onInputChange({ name, value });
      }
    },
    [onInputChange]
  );

  const handleConfirmAllowRfc1918 = useCallback(() => {
    setIsConfirmAllowRfc1918ModalOpen(false);

    onInputChange({
      name: 'allowRfc1918UrlsFromExternalSources',
      value: true,
    });
  }, [onInputChange]);

  const handleCancelAllowRfc1918 = useCallback(() => {
    setIsConfirmAllowRfc1918ModalOpen(false);
  }, []);

  const handleAuthenticationRequiredChange = useCallback(
    ({ name, value }: InputChanged<string>) => {
      // Only interrupt with a warning when moving TO a less-secure state;
      // moving back to Enabled or disabledForLocalHost is always safe and
      // needs no confirmation.
      if (riskyAuthenticationRequiredValues.includes(value)) {
        setPendingAuthenticationRequiredValue(value);
        setIsConfirmAuthenticationRequiredModalOpen(true);
      } else {
        onInputChange({ name, value });
      }
    },
    [onInputChange]
  );

  const handleConfirmAuthenticationRequired = useCallback(() => {
    setIsConfirmAuthenticationRequiredModalOpen(false);

    if (pendingAuthenticationRequiredValue !== null) {
      onInputChange({
        name: 'authenticationRequired',
        value: pendingAuthenticationRequiredValue,
      });
    }

    setPendingAuthenticationRequiredValue(null);
  }, [onInputChange, pendingAuthenticationRequiredValue]);

  const handleCancelAuthenticationRequired = useCallback(() => {
    setIsConfirmAuthenticationRequiredModalOpen(false);
    setPendingAuthenticationRequiredValue(null);
  }, []);

  // createCommandExecutingSelector(CommandNames.RESET_API_KEY),

  const authenticationEnabled =
    authenticationMethod && authenticationMethod.value !== 'none';
  const isCustomTrustLevel =
    xForwardedForTrustLevel && xForwardedForTrustLevel.value === 'custom';
  const isCustomAuthenticationRequired =
    authenticationRequired &&
    authenticationRequired.value === 'disabledForCustomAddresses';

  return (
    <FieldSet legend={translate('Security')}>
      <FormGroup>
        <FormLabel>{translate('Authentication')}</FormLabel>

        <FormInputGroup
          type={inputTypes.SELECT}
          name="authenticationMethod"
          values={authenticationMethodOptions}
          helpText={translate('AuthenticationMethodHelpText')}
          helpTextWarning={translate('AuthenticationRequiredWarning')}
          onChange={onInputChange}
          {...authenticationMethod}
        />
      </FormGroup>

      {authenticationEnabled ? (
        <FormGroup>
          <FormLabel>{translate('AuthenticationRequired')}</FormLabel>

          <FormInputGroup
            type={inputTypes.SELECT}
            name="authenticationRequired"
            values={authenticationRequiredOptions}
            helpText={translate('AuthenticationRequiredHelpText')}
            onChange={handleAuthenticationRequiredChange}
            {...authenticationRequired}
          />
        </FormGroup>
      ) : null}

      {authenticationEnabled && isCustomAuthenticationRequired ? (
        <FormGroup>
          <FormLabel>{translate('AuthenticationRequiredCidrs')}</FormLabel>

          <FormInputGroup
            type={inputTypes.TEXT}
            name="authenticationRequiredCidrs"
            helpText={translate('AuthenticationRequiredCidrsHelpText')}
            onChange={onInputChange}
            {...authenticationRequiredCidrs}
          />
        </FormGroup>
      ) : null}

      {authenticationEnabled ? (
        <FormGroup>
          <FormLabel>{translate('Username')}</FormLabel>

          <FormInputGroup
            type={inputTypes.TEXT}
            name="username"
            onChange={onInputChange}
            {...username}
          />
        </FormGroup>
      ) : null}

      {authenticationEnabled ? (
        <FormGroup>
          <FormLabel>{translate('Password')}</FormLabel>

          <FormInputGroup
            type={inputTypes.PASSWORD}
            name="password"
            onChange={onInputChange}
            {...password}
          />
        </FormGroup>
      ) : null}

      {authenticationEnabled ? (
        <FormGroup>
          <FormLabel>{translate('PasswordConfirmation')}</FormLabel>

          <FormInputGroup
            type={inputTypes.PASSWORD}
            name="passwordConfirmation"
            onChange={onInputChange}
            {...passwordConfirmation}
          />
        </FormGroup>
      ) : null}

      <FormGroup>
        <FormLabel>{translate('ApiKey')}</FormLabel>

        <FormInputGroup
          type={inputTypes.TEXT}
          name="apiKey"
          readOnly={true}
          helpTextWarning={translate('RestartRequiredHelpTextWarning')}
          buttons={[
            <ClipboardButton
              key="copy"
              value={apiKey.value}
              kind={kinds.DEFAULT}
            />,

            <FormInputButton
              key="reset"
              kind={kinds.DANGER}
              onPress={handleResetApiKeyPress}
            >
              <Icon name={icons.REFRESH} isSpinning={isResettingApiKey} />
            </FormInputButton>,
          ]}
          onChange={onInputChange}
          onFocus={handleApikeyFocus}
          {...apiKey}
        />
      </FormGroup>

      <FormGroup>
        <FormLabel>{translate('CertificateValidation')}</FormLabel>

        <FormInputGroup
          type={inputTypes.SELECT}
          name="certificateValidation"
          values={certificateValidationOptions}
          helpText={translate('CertificateValidationHelpText')}
          onChange={onInputChange}
          {...certificateValidation}
        />
      </FormGroup>

      <FormGroup advancedSettings={showAdvancedSettings} isAdvanced={true}>
        <FormLabel>{translate('XForwardedForTrustLevel')}</FormLabel>

        <FormInputGroup
          type={inputTypes.SELECT}
          name="xForwardedForTrustLevel"
          values={xForwardedForTrustLevelOptions}
          helpText={translate('XForwardedForTrustLevelHelpText')}
          helpTextWarning={translate('RestartRequiredHelpTextWarning')}
          onChange={onInputChange}
          {...xForwardedForTrustLevel}
        />
      </FormGroup>

      {isCustomTrustLevel ? (
        <FormGroup advancedSettings={showAdvancedSettings} isAdvanced={true}>
          <FormLabel>{translate('TrustedProxyCidrs')}</FormLabel>

          <FormInputGroup
            type={inputTypes.TEXT}
            name="trustedProxyCidrs"
            helpText={translate('TrustedProxyCidrsHelpText')}
            helpTextWarning={translate('RestartRequiredHelpTextWarning')}
            onChange={onInputChange}
            {...trustedProxyCidrs}
          />
        </FormGroup>
      ) : null}

      <FormGroup advancedSettings={showAdvancedSettings} isAdvanced={true}>
        <FormLabel>
          {translate('AllowRfc1918UrlsFromExternalSources')}
        </FormLabel>

        <FormInputGroup
          type={inputTypes.CHECK}
          name="allowRfc1918UrlsFromExternalSources"
          helpText={translate('AllowRfc1918UrlsFromExternalSourcesHelpText')}
          helpTextWarning={translate(
            'AllowRfc1918UrlsFromExternalSourcesWarning'
          )}
          onChange={handleAllowRfc1918Change}
          {...allowRfc1918UrlsFromExternalSources}
        />
      </FormGroup>

      <ConfirmModal
        isOpen={isConfirmApiKeyResetModalOpen}
        kind={kinds.DANGER}
        title={translate('ResetAPIKey')}
        message={translate('ResetAPIKeyMessageText')}
        confirmLabel={translate('Reset')}
        onConfirm={handleConfirmResetApiKey}
        onCancel={handleCloseResetApiKeyModal}
      />

      <ConfirmModal
        isOpen={isConfirmAllowRfc1918ModalOpen}
        kind={kinds.DANGER}
        title={translate('AllowRfc1918UrlsFromExternalSourcesConfirmTitle')}
        message={translate(
          'AllowRfc1918UrlsFromExternalSourcesConfirmMessage'
        )}
        confirmLabel={translate('IUnderstand')}
        onConfirm={handleConfirmAllowRfc1918}
        onCancel={handleCancelAllowRfc1918}
      />

      <ConfirmModal
        isOpen={isConfirmAuthenticationRequiredModalOpen}
        kind={kinds.DANGER}
        title={translate('AuthenticationRequiredConfirmTitle')}
        message={translate('AuthenticationRequiredConfirmMessage')}
        confirmLabel={translate('IUnderstand')}
        onConfirm={handleConfirmAuthenticationRequired}
        onCancel={handleCancelAuthenticationRequired}
      />
    </FieldSet>
  );
}

export default SecuritySettings;
