using Microsoft.UI.Xaml;
using Microsoft.UI.Xaml.Controls;
using XeonV3Control.App.Hardware;
using XeonV3Control.Core;

namespace XeonV3Control.App;

public sealed partial class MainWindow
{
    private void ShowTpmOverview(TpmFirmwareReport report)
    {
        StackPanel card = Card(Results, text["TpmOverview"]);
        AddRow(card, text["TpmFirmwareStatus"], TpmFirmwareStatusText(report.Status));
        AddRow(card, text["TpmDebugDriver"], text[report.DebugDriverInstalled ? "Installed" : "NotInstalled"]);
        AddRow(card, text["TpmFirmwareEvidenceCount"], report.Evidence.Count.ToString("N0", text.Culture));
        if (report.Descriptor.Available)
        {
            AddRow(card, text["TpmTransport"], TpmTransportText(report.Descriptor.Transport));
            if (report.Descriptor.PchStraps.Count > 1)
            {
                AddRow(card, "PCHSTRP1", $"0x{report.Descriptor.PchStraps[1]:X8}");
            }
        }
        try
        {
            TpmBootDebugReport? bootReport = UefiTpmDebugReportReader.TryRead();
            if (bootReport is not null)
            {
                AddRow(card, text["TpmDiagnosticReason"], text["TpmReason" + bootReport.Reason]);
                AddRow(card, text["TpmTisDidVid"], $"0x{bootReport.TisDidVid:X8}");
                if (bootReport.ReportVersion >= 2)
                {
                    AddRow(card, text["TpmPackages"], bootReport.PackageCount.ToString(text.Culture));
                    if (bootReport.AcpiDeviceFound)
                    {
                        AddRow(card, text["TpmAcpiDevicePath"], string.IsNullOrWhiteSpace(bootReport.AcpiDevicePath) ? text["NotAvailable"] : bootReport.AcpiDevicePath);
                    }
                }
            }
        }
        catch (Exception error)
        {
            AppLog.Error(error);
        }
        var button = new Button
        {
            Content = IconText(UiGlyphs.Navigate, text["OpenTpm"]),
            HorizontalAlignment = HorizontalAlignment.Left
        };
        button.Click += (_, _) => NavigateTo(WorkspacePage.Tpm);
        Microsoft.UI.Xaml.Automation.AutomationProperties.SetName(button, text["OpenTpm"]);
        card.Children.Add(button);
    }

    private void ShowTpmDetails(TpmFirmwareReport report)
    {
        StackPanel firmware = Card(TpmResults, text["TpmFirmwareImageEvidence"]);
        AddRow(firmware, text["TpmFirmwareStatus"], TpmFirmwareStatusText(report.Status));
        AddRow(firmware, text["TpmDebugDriver"], text[report.DebugDriverInstalled ? "Installed" : "NotInstalled"]);
        AddRow(firmware, text["TpmDebugDriverCopies"], report.DebugDriverCopies.ToString("N0", text.Culture));
        if (report.Evidence.Count == 0)
        {
            firmware.Children.Add(Label(text["TpmNoImageEvidence"]));
        }
        else
        {
            foreach (TpmFirmwareEvidence evidence in report.Evidence)
            {
                AddRow(firmware, evidence.Key, evidence.Occurrences.ToString("N0", text.Culture));
            }
        }

        StackPanel descriptor = Card(TpmResults, text["TpmDescriptorDiagnostics"]);
        if (!report.Descriptor.Available)
        {
            descriptor.Children.Add(Label(text["TpmDescriptorUnavailable"]));
        }
        else
        {
            AddRow(descriptor, text["TpmTransport"], TpmTransportText(report.Descriptor.Transport));
            AddRow(descriptor, text["TpmPchStrapBase"], $"0x{report.Descriptor.PchStrapBase:X}");
            AddRow(descriptor, text["TpmPchStrapCount"], $"{report.Descriptor.PchStraps.Count} / {report.Descriptor.DeclaredStrapCount}");
            for (int index = 0; index < report.Descriptor.PchStraps.Count; index++)
            {
                AddRow(descriptor, $"PCHSTRP{index}", $"0x{report.Descriptor.PchStraps[index]:X8}");
            }
            descriptor.Children.Add(Label(text["TpmTransportRawHint"]));
        }

        StackPanel driver = Card(TpmResults, text["TpmDebugDriverControl"]);
        driver.Children.Add(Notice(text["TpmDebugDriverPassiveTitle"], text["TpmDebugDriverPassiveMessage"], InfoBarSeverity.Informational));
        var mutate = new Button
        {
            Content = report.DebugDriverInstalled ? text["TpmRemoveDebugDriver"] : text["TpmInstallDebugDriver"],
            HorizontalAlignment = HorizontalAlignment.Left,
            IsEnabled = !activeImage!.UefiDrivers.Incomplete && report.DebugDriverCopies <= 1
        };
        mutate.Click += MutateTpmDebugDriver;
        Microsoft.UI.Xaml.Automation.AutomationProperties.SetName(mutate, mutate.Content?.ToString() ?? text["TpmDebugDriver"]);
        driver.Children.Add(mutate);

        StackPanel boot = Card(TpmResults, text["TpmBootDiagnosticReport"]);
        try
        {
            TpmBootDebugReport? bootReport = UefiTpmDebugReportReader.TryRead();
            if (bootReport is null)
            {
                boot.Children.Add(Notice(text["TpmNoBootReportTitle"], text["TpmNoBootReportMessage"], InfoBarSeverity.Informational));
                return;
            }
            AddRow(boot, text["TpmDiagnosticReason"], text["TpmReason" + bootReport.Reason]);
            AddRow(boot, text["TpmReportVersion"], bootReport.ReportVersion.ToString(text.Culture));
            AddRow(boot, text["TpmReportStage"], text[bootReport.ReadyToBootSnapshot ? "TpmReportStageReadyToBoot" : "TpmReportStageEarlyDxe"]);
            AddRow(boot, text["TpmRootBridges"], bootReport.RootBridgeCount.ToString(text.Culture));
            AddRow(boot, text["TpmLpcId"], $"0x{bootReport.LpcVendorDevice:X8}");
            AddRow(boot, text["TpmLpcRcba"], $"0x{bootReport.LpcRcba:X8}");
            string[] decodeNames = ["80/82", "84", "88", "8C", "90", "98"];
            AddRow(boot, text["TpmLpcDecodeRegisters"], string.Join(" · ", bootReport.LpcDecodeRegisters.Select((v, i) => $"{decodeNames[i]}=0x{v:X8}")));

            if (bootReport.ReportVersion >= 3)
            {
                AddRow(boot, text["TpmMmioDiagnosis"], TpmMmioDiagnosisText(bootReport));
                StackPanel bridges = Card(TpmResults, text["TpmRootBridgeDetails"]);
                AddRow(bridges, text["TpmRootBridgeStored"], $"{bootReport.RootBridgeStoredCount} / {bootReport.RootBridgeCount}");
                AddRow(bridges, text["TpmRootBridgeChosen"], bootReport.ChosenRootBridgeIndex == uint.MaxValue
                    ? text["NotAvailable"] : $"#{bootReport.ChosenRootBridgeIndex}");
                for (int index = 0; index < bootReport.RootBridges.Count; index++)
                {
                    TpmBootRootBridge root = bootReport.RootBridges[index];
                    string bus = root.BusRangeAvailable ? $"{root.BusMin:X2}-{root.BusMax:X2}" : text["NotAvailable"];
                    string flags = root.Chosen ? text["TpmRootBridgeSelected"] : root.WellsburgLpc ? text["TpmRootBridgeWellsburg"] : text["TpmRootBridgeOther"];
                    string segment = root.SegmentNumber == uint.MaxValue ? text["NotAvailable"] : root.SegmentNumber.ToString(text.Culture);
                    AddRow(bridges, $"RB#{index}",
                        $"SEG={segment}; BUS={bus}; D31:F0=0x{root.LpcVendorDevice:X8}; {flags}; " +
                        $"EFI_STATUS Handle=0x{root.HandleProtocolStatus:X16}, Config=0x{root.ConfigurationStatus:X16}, LPC=0x{root.LpcReadStatus:X16}");
                }

                StackPanel pch = Card(TpmResults, text["TpmRcbaSnapshot"]);
                AddRow(pch, "GCS @ +3410", TpmRegisterSnapshot(bootReport.RcbaGcsAvailable, bootReport.RcbaGcs, bootReport.RcbaGcsReadStatus));
                AddRow(pch, "FD @ +3418", TpmRegisterSnapshot(bootReport.RcbaFunctionDisableAvailable, bootReport.RcbaFunctionDisable, bootReport.RcbaFunctionDisableReadStatus));
                AddRow(pch, "SPI BFPR @ +3800", TpmRegisterSnapshot(bootReport.RcbaSpiBfprAvailable, bootReport.RcbaSpiBfpr, bootReport.RcbaSpiBfprReadStatus));
                AddRow(pch, "SPI HSFS/HSFC @ +3804", TpmRegisterSnapshot(bootReport.RcbaSpiHsfsHsfcAvailable, bootReport.RcbaSpiHsfsHsfc, bootReport.RcbaSpiHsfsHsfcReadStatus));
                pch.Children.Add(Label(text["TpmRcbaSnapshotHint"]));
            }

            if (bootReport.ReportVersion >= 2)
            {
                AddRow(boot, text["TpmMpServices"], YesNo(bootReport.MpServicesAvailable));
                AddRow(boot, text["TpmProcessors"], bootReport.ProcessorCount.ToString(text.Culture));
                AddRow(boot, text["TpmEnabledProcessors"], bootReport.EnabledProcessorCount.ToString(text.Culture));
                AddRow(boot, text["TpmPackages"], bootReport.PackageCount.ToString(text.Culture));
                AddRow(boot, text["TpmMpStatuses"], $"Locate=0x{bootReport.MpServicesLocateStatus:X16}; GetNumber=0x{bootReport.MpGetNumberStatus:X16}");

                AddRow(boot, text["TpmAcpiDevicePath"], bootReport.AcpiDeviceFound && !string.IsNullOrWhiteSpace(bootReport.AcpiDevicePath)
                    ? bootReport.AcpiDevicePath : text["NotAvailable"]);
                AddRow(boot, text["TpmAcpiInferredHid"], bootReport.InferredAcpiHid ?? text["NotAvailable"]);
                AddRow(boot, text["TpmAcpiInferredSta"], bootReport.InferredAcpiSta is ulong inferredSta
                    ? $"0x{inferredSta:X} ({text[((inferredSta & 1UL) != 0) ? "TpmAcpiStaPresent" : "TpmAcpiStaAbsent"]})"
                    : text["NotAvailable"]);
                AddRow(boot, text["TpmAcpiInferredStr"], bootReport.InferredAcpiStr ?? text["NotAvailable"]);
                AddRow(boot, text["TpmAcpiSta"], TpmAcpiStaText(bootReport));
                AddRow(boot, text["TpmAcpiCrs"], TpmAcpiCrsText(bootReport));
                AddRow(boot, text["TpmAcpiCrsMmio"], bootReport.AcpiCrsMemoryAvailable
                    ? $"0x{bootReport.AcpiCrsMemoryBase:X16} + 0x{bootReport.AcpiCrsMemoryLength:X}" : text["NotAvailable"]);
                AddRow(boot, text["TpmAcpiCrsIrq"], bootReport.AcpiCrsIrqAvailable
                    ? $"{bootReport.AcpiCrsIrq} ({bootReport.AcpiCrsIrqCount} {text["TpmResources"]})" : text["NotAvailable"]);
                AddRow(boot, text["TpmAcpiCid"], TpmAcpiIdText(bootReport.AcpiCidPresent, bootReport.AcpiCidStringAvailable,
                    bootReport.AcpiCidIntegerAvailable, bootReport.AcpiCidString, bootReport.AcpiCidValue));
                AddRow(boot, text["TpmAcpiUid"], TpmAcpiIdText(bootReport.AcpiUidPresent, bootReport.AcpiUidStringAvailable,
                    bootReport.AcpiUidIntegerAvailable, bootReport.AcpiUidString, bootReport.AcpiUidValue));
                AddRow(boot, text["TpmAcpiDsm"], YesNo(bootReport.AcpiDsmPresent));
                AddRow(boot, text["TpmAcpiDeviceRange"], bootReport.AcpiDeviceFound
                    ? $"DSDT AML +0x{bootReport.AcpiMsftDeviceOffset:X} / 0x{bootReport.AcpiMsftDeviceLength:X} {text["TpmBytes"]}"
                    : text["NotAvailable"]);
                AddRow(boot, "TCMF", TpmAcpiPolicyValue(bootReport.AcpiTcmfAvailable, bootReport.AcpiTcmfValue));
                AddRow(boot, "TTPF", TpmAcpiPolicyValue(bootReport.AcpiTtpfAvailable, bootReport.AcpiTtpfValue));
                AddRow(boot, "DTPT", TpmAcpiPolicyValue(bootReport.AcpiDtptAvailable, bootReport.AcpiDtptValue));
                AddRow(boot, "TTDP", TpmAcpiPolicyValue(bootReport.AcpiTtdpAvailable, bootReport.AcpiTtdpValue));
                AddRow(boot, "AMDT", TpmAcpiPolicyValue(bootReport.AcpiAmdtAvailable, bootReport.AcpiAmdtValue));
                AddRow(boot, "TPMF", TpmAcpiPolicyValue(bootReport.AcpiTpmfAvailable, bootReport.AcpiTpmfValue));
                AddRow(boot, "TPMM", TpmAcpiPolicyValue(bootReport.AcpiTpmmAvailable, bootReport.AcpiTpmmValue));
                AddRow(boot, "FTPM", TpmAcpiPolicyValue(bootReport.AcpiFtpmAvailable, bootReport.AcpiFtpmValue));
                boot.Children.Add(Label(text["TpmAcpiPolicyHint"]));

                StackPanel localities = Card(TpmResults, text["TpmLocalities"]);
                AddRow(localities, text[bootReport.ReportVersion >= 3 ? "TpmLocalityReadSuccessMask" : "TpmLocalityReadableMask"], $"0x{bootReport.LocalityReadableMask:X2}");
                AddRow(localities, text["TpmLocalityRespondingMask"], $"0x{bootReport.LocalityRespondingMask:X2}");
                for (int index = 0; index < bootReport.Localities.Count; index++)
                {
                    TpmBootLocality locality = bootReport.Localities[index];
                    ulong address = 0xFED40000UL + ((ulong)index * 0x1000UL);
                    string state = locality.Responding ? text["TpmLocalityResponding"] : text["TpmLocalityNoResponse"];
                    string statuses = locality.ReadStatuses is TpmBootLocalityReadStatuses readStatuses
                        ? $"; EFI_STATUS A=0x{readStatuses.Access:X16}, STS=0x{readStatuses.Status:X16}, DID=0x{readStatuses.DidVid:X16}, IF=0x{readStatuses.InterfaceId:X16}, RID=0x{readStatuses.Rid:X16}"
                        : string.Empty;
                    AddRow(localities, $"L{index} @ 0x{address:X8}",
                        $"{state}; ACCESS=0x{locality.Access:X2}; RID=0x{locality.Rid:X2}; STS=0x{locality.Status:X8}; DID_VID=0x{locality.DidVid:X8}; IF=0x{locality.InterfaceId:X8}{statuses}");
                }
            }

            AddRow(boot, text["TpmTcg2Present"], YesNo((bootReport.Flags & 1u) != 0));
            string capabilityUnavailable = text["NotAvailable"];
            AddRow(boot, text["TpmTcg2TpmPresent"], bootReport.Tcg2CapabilityAvailable ? YesNo(bootReport.Tcg2PresentFlag != 0) : capabilityUnavailable);
            AddRow(boot, text["TpmTcg2Version"], bootReport.Tcg2CapabilityAvailable ? $"{bootReport.Tcg2ProtocolMajor}.{bootReport.Tcg2ProtocolMinor}" : capabilityUnavailable);
            AddRow(boot, text["TpmManufacturerId"], bootReport.Tcg2CapabilityAvailable ? $"0x{bootReport.Tcg2ManufacturerId:X8}" : capabilityUnavailable);
            AddRow(boot, text["TpmPcrBanks"], bootReport.Tcg2CapabilityAvailable ? $"{bootReport.Tcg2NumberOfPcrBanks} / 0x{bootReport.Tcg2ActivePcrBanks:X8}" : capabilityUnavailable);
            AddRow(boot, text["TpmAcpiTables"], $"TPM2={bootReport.Tpm2TableCount}; TCPA={bootReport.TcpaTableCount}; MSFT0101={bootReport.Msft0101Count}");
            AddRow(boot, text["TpmStartMethod"], bootReport.Tpm2StartMethod.ToString(text.Culture));
            AddRow(boot, text["TpmControlArea"], $"0x{bootReport.Tpm2ControlArea:X16} / 0x{bootReport.Tpm2ControlValue:X8}");
            AddRow(boot, text["TpmTisAccess"], $"0x{bootReport.TisAccess:X2}");
            AddRow(boot, text["TpmTisStatus"], $"0x{bootReport.TisStatus:X8}");
            AddRow(boot, text["TpmTisDidVid"], $"0x{bootReport.TisDidVid:X8}");
            AddRow(boot, text["TpmPtpInterfaceId"], $"0x{bootReport.PtpInterfaceId:X8}");
            AddRow(boot, text["TpmEfiStatuses"],
                $"TCG2=0x{bootReport.Tcg2LocateStatus:X16}; cap=0x{bootReport.Tcg2CapabilityStatus:X16}; ACPI=0x{bootReport.AcpiStatus:X16}; TIS=0x{bootReport.TisRegisterReadStatus:X16}");
        }
        catch (Exception error)
        {
            AppLog.Error(error);
            boot.Children.Add(Notice(text["TpmBootReportReadErrorTitle"], error.Message, InfoBarSeverity.Warning));
        }
    }

    private async void MutateTpmDebugDriver(object sender, RoutedEventArgs args)
    {
        _ = sender;
        _ = args;
        if (operation is not null || activeImage is not BiosImage sourceImage)
        {
            return;
        }
        await RunOperation(async token =>
        {
            byte[] bytes = await File.ReadAllBytesAsync(sourceImage.FilePath, token);
            TpmDebugDriverPlan plan = await Task.Run(() => TpmDebugDriverImageUpdater.Plan(bytes, sourceImage, token), token);
            if (!plan.CanExecute)
            {
                throw new InvalidDataException("TpmDebugMutationBlocked");
            }
            TemporaryBiosArtifact artifact = plan.Mutation == TpmDebugDriverMutation.Install
                ? TemporaryBiosArtifact.TpmDebugInstall
                : TemporaryBiosArtifact.TpmDebugRemoval;
            string destination = temporary.NewBiosPath(artifact);
            BiosImage updated = await TpmDebugDriverImageUpdater.ApplyFileAsync(sourceImage.FilePath, destination, plan, token);
            ShowImage(updated, ImageSourceKind.UpdatedImage, WorkspacePage.Tpm);
            SetNotice(TpmNoticeBar, text["Completed"],
                text[plan.Mutation == TpmDebugDriverMutation.Install ? "TpmDebugInstalledMessage" : "TpmDebugRemovedMessage"],
                InfoBarSeverity.Success);
        }, UiOperationKind.UpdatingTpmDebugDriver);
    }

    private string TpmFirmwareStatusText(TpmFirmwareSupportStatus status) => text["TpmFirmwareStatus" + status];
    private string YesNo(bool value) => text[value ? "Yes" : "No"];

    private string TpmTransportText(TpmTransportHint transport) => text[transport switch
    {
        TpmTransportHint.Lpc => "TpmTransportLpc",
        TpmTransportHint.Spi => "TpmTransportSpi",
        _ => "TpmTransportUnknown"
    }];

    private string TpmAcpiStaText(TpmBootDebugReport report)
    {
        if (report.AcpiStaStatic)
        {
            return $"0x{report.AcpiStaValue:X} ({text[((report.AcpiStaValue & 1UL) != 0) ? "TpmAcpiStaPresent" : "TpmAcpiStaAbsent"]})";
        }
        return report.AcpiStaMethod ? text["TpmAcpiMethodNotEvaluated"] : text["NotAvailable"];
    }

    private string TpmAcpiCrsText(TpmBootDebugReport report)
    {
        if (report.AcpiCrsBuffer)
        {
            return $"{text["TpmAcpiStaticBuffer"]}: {report.AcpiCrsBufferLength.ToString("N0", text.Culture)} {text["TpmBytes"]}";
        }
        return report.AcpiCrsMethod ? text["TpmAcpiMethodNotEvaluated"] : text["NotAvailable"];
    }

    private string TpmAcpiIdText(bool present, bool hasString, bool hasInteger, string stringValue, ulong integerValue)
    {
        if (!present) return text["NotAvailable"];
        if (hasString) return stringValue;
        if (hasInteger) return $"0x{integerValue:X}";
        return text["TpmAcpiPresentDynamic"];
    }

    private string TpmRegisterSnapshot(bool available, uint value, ulong status) =>
        available ? $"0x{value:X8}; EFI_STATUS=0x{status:X16}" : $"{text["NotAvailable"]}; EFI_STATUS=0x{status:X16}";

    private string TpmMmioDiagnosisText(TpmBootDebugReport report)
    {
        if (report.LocalityRespondingMask != 0)
        {
            return $"{text["TpmMmioResponding"]}: 0x{report.LocalityRespondingMask:X2}";
        }
        return (report.LocalityReadableMask & 0x1Fu) == 0x1Fu
            ? text["TpmMmioAllReadsNoResponse"]
            : text["TpmMmioReadFailures"];
    }

    private string TpmAcpiPolicyValue(bool available, ulong value) =>
        available ? $"0x{value:X} ({value.ToString(text.Culture)})" : text["NotAvailable"];
}
